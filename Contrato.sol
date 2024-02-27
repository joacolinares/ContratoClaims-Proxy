// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

//import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
//import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./Treasury.sol";


///////Redirige todas las llamadas y transacciones a una implementación específica almacenada en slots de almacenamiento////
contract ProxyClaims {

    // 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint(keccak256("eip1967.proxy.implementation")) - 1);
    // 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
    bytes32 private constant ADMIN_SLOT =
        bytes32(uint(keccak256("eip1967.proxy.admin")) - 1);

    constructor() {
        _setAdmin(msg.sender);
    }

    modifier ifAdmin() {
        if (msg.sender == _getAdmin()) {
            _;
        } else {
            _fallback();
        }
    }

    function _getAdmin() private view returns (address) {
        return StorageSlot.getAddressSlot(ADMIN_SLOT).value;
    }

    function _setAdmin(address _admin) private {
        require(_admin != address(0), "admin = zero address");
        StorageSlot.getAddressSlot(ADMIN_SLOT).value = _admin;
    }

    function _getImplementation() private view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }

    function _setImplementation(address _implementation) private {
        require(_implementation.code.length > 0, "implementation is not contract");
        StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value = _implementation;
    }

    // Admin interface //
    function changeAdmin(address _admin) external ifAdmin {
        _setAdmin(_admin);
    }

    // 0x3659cfe6
    function upgradeTo(address _implementation) external ifAdmin {
        _setImplementation(_implementation);
    }

    // 0xf851a440
    function admin() external ifAdmin returns (address) {
        return _getAdmin();
    }

    // 0x5c60da1b
    function implementation() external ifAdmin returns (address) {
        return _getImplementation();
    }

    function _delegate(address _implementation) internal virtual {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    function _fallback() private {
        _delegate(_getImplementation());
    }

    fallback() external payable {
        _fallback();
    }

    receive() external payable {
        _fallback();
    }
}



//////Facilita la administración y actualización del contrato proxy////
contract ProxyAdminClaims {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function getProxyAdmin(address proxy) external view returns (address) {
        (bool ok, bytes memory res) = proxy.staticcall(abi.encodeCall(ProxyClaims.admin, ()));
        require(ok, "call failed");
        return abi.decode(res, (address));
    }

    function getProxyImplementation(address proxy) external view returns (address) {
        (bool ok, bytes memory res) = proxy.staticcall(
            abi.encodeCall(ProxyClaims.implementation, ())
        );
        require(ok, "call failed");
        return abi.decode(res, (address));
    }

    function changeProxyAdmin(address payable proxy, address admin) external onlyOwner {
        ProxyClaims(proxy).changeAdmin(admin);
    }

    function upgrade(address payable proxy, address implementation) external onlyOwner {
        ProxyClaims(proxy).upgradeTo(implementation);
    }
}



/////Permite acceder a slots de almacenamiento de la blockchain////////
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    function getAddressSlot(
        bytes32 slot
    ) internal pure returns (AddressSlot storage r) {
        assembly {
            r.slot := slot
        }
    }
}




////Contrato//////



bytes32 constant OWNER_ROLE = 0;
bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
bytes32 constant INVESTOR_ROLE = keccak256("INVESTOR_ROLE");

// StakeInfo flags
uint8 constant STAKE_ACTIVE = 1;

struct StakeInfo {
    uint128 amount;
    uint64 endTime;
    uint8 flags;
}

struct PerformanceFeeBracket {
    uint128 max;
    uint16 feeTimes10k;
}

struct PerformanceFeeRecipient {
    address addr;
    uint32 shares;
}


contract Claims is Initializable, AccessControlUpgradeable {

    uint256 public numTest;
    function setNum(uint256 _num) public{
        numTest = _num;
    }

    using SafeERC20 for IERC20;

    event GlobalMinDepositChanged(uint256 newMin);

    event Staked(uint32 indexed time, uint32 indexed stakeId, uint256 amount);
    event Unstaked(uint32 indexed stakeId, uint256 amount);
    event ClaimedProfit(address indexed user, uint256 amount);
    event ClaimedPerformanceFee(address indexed user, uint256 amount);
    event ProfitDeposited(uint256 amount, uint256 pendingPerformanceFee);
    event PerformanceFeeDeposited(uint256 amount);
    event StakeReturned(uint256 amount);

    error AmountIsZero();
    error AmountBelowMinimum();
    error TimeNotAllowed();
    error StakeNotFinished();
    error StakeDoesntExist();
    error NotEnoughBalance();

    uint32 nextStakeId;
    IERC20 public token;
    Treasury treasury;
    uint256 public totalStaked;
    uint32[] allowedStakingTimes;
    mapping(uint32 => StakeInfo) public stakes;
    PerformanceFeeBracket[] performanceFeeBrackets;
    PerformanceFeeRecipient[][] performanceFeeRecipients;
    uint256[] public totalPerformanceFeeShares;
    uint256 public profitAvailable;
    mapping(address => uint256) public performanceFeeAvailable;
    uint256 public globalMinDeposit;
    uint256 public availableForUnstaking;

    function initialize(IERC20 token_, Treasury treasury_) public initializer {
        __AccessControl_init();
        _grantRole(OWNER_ROLE, msg.sender);
        token = token_;
        treasury = treasury_;
    }

    function getAllowedStakingTimes() external view returns (uint32[] memory) {
        return allowedStakingTimes;
    }

    function getPerformanceFeeBrackets()
        external
        view
        returns (PerformanceFeeBracket[] memory)
    {
        return performanceFeeBrackets;
    }

    function getPerformanceFeeRecipients(
        uint256 bracketIndex
    ) external view returns (PerformanceFeeRecipient[] memory) {
        return performanceFeeRecipients[bracketIndex];
    }

    function getCurrentPerformanceFee()
        external
        view
        returns (uint256 feeTimes10k)
    {
        uint256 totalFeeTimes100m = 0;
        uint256 prevMax = 0;
        if (totalStaked == 0 && performanceFeeBrackets.length > 0)
            return performanceFeeBrackets[0].feeTimes10k;
        for (uint i = 0; i < performanceFeeBrackets.length; i++) {
            PerformanceFeeBracket storage bracket = performanceFeeBrackets[i];
            uint256 bracketEnd = (totalStaked < bracket.max)
                ? totalStaked
                : bracket.max;
            uint256 range = bracketEnd - prevMax;
            uint256 fractionTimes10k = (range * 10_000) / totalStaked;
            totalFeeTimes100m += bracket.feeTimes10k * fractionTimes10k;
            if (bracket.max >= totalStaked) break;
            prevMax = bracket.max;
        }
        return totalFeeTimes100m / 10_000;
    }

    function enableStakingTime(uint32 time) external onlyRole(OWNER_ROLE) {
        for (uint i = 0; i < allowedStakingTimes.length; i++)
            if (allowedStakingTimes[i] == time) return;
        allowedStakingTimes.push(time);
    }

    function disableStakingTime(uint32 time) external onlyRole(OWNER_ROLE) {
        for (uint i = 0; i < allowedStakingTimes.length; i++) {
            if (allowedStakingTimes[i] == time) {
                allowedStakingTimes[i] = allowedStakingTimes[
                    allowedStakingTimes.length - 1
                ];
                allowedStakingTimes.pop();
                break;
            }
        }
    }

    function addPerformanceFeeBracket(
        uint128 max,
        uint16 feeTimes10k
    ) external onlyRole(OWNER_ROLE) {
        uint index = 0;
        while (
            index < performanceFeeBrackets.length &&
            performanceFeeBrackets[index].max < max
        ) index++;
        require(
            index == performanceFeeBrackets.length ||
                performanceFeeBrackets[index].max != max
        );
        performanceFeeBrackets.push();
        performanceFeeRecipients.push();
        totalPerformanceFeeShares.push(0);
        for (uint256 i = performanceFeeBrackets.length - 1; i > index; i--)
            performanceFeeBrackets[i] = performanceFeeBrackets[i - 1];
        editPerformanceFeeBracket(index, max, feeTimes10k);
    }

    function editPerformanceFeeBracket(
        uint256 index,
        uint128 max,
        uint16 feeTimes10k
    ) public onlyRole(OWNER_ROLE) {
        require(
            index < performanceFeeBrackets.length &&
                max > 0 &&
                feeTimes10k < 10_000
        );
        if (index + 1 < performanceFeeBrackets.length)
            require(max < performanceFeeBrackets[index + 1].max);
        if (index > 0) require(max > performanceFeeBrackets[index - 1].max);
        performanceFeeBrackets[index] = PerformanceFeeBracket({
            max: max,
            feeTimes10k: feeTimes10k
        });
    }

    function removePerformanceFeeBracket(
        uint256 index
    ) external onlyRole(OWNER_ROLE) {
        for (uint256 i = index; i < performanceFeeBrackets.length - 1; i++)
            performanceFeeBrackets[i] = performanceFeeBrackets[i + 1];
        performanceFeeBrackets.pop();
        performanceFeeRecipients.pop();
        totalPerformanceFeeShares.pop();
    }

    function setPerformanceFeeRecipientShares(
        uint256 bracketIndex,
        address recipient,
        uint32 shares
    ) external onlyRole(OWNER_ROLE) {
        require(bracketIndex < performanceFeeRecipients.length);
        PerformanceFeeRecipient[] storage recipients = performanceFeeRecipients[
            bracketIndex
        ];
        for (uint i = 0; i < recipients.length; i++) {
            if (recipients[i].addr == recipient) {
                totalPerformanceFeeShares[bracketIndex] =
                    totalPerformanceFeeShares[bracketIndex] +
                    shares -
                    recipients[i].shares;
                if (shares == 0) {
                    recipients[i] = recipients[recipients.length - 1];
                    recipients.pop();
                } else {
                    recipients[i].shares = shares;
                }
                return;
            }
        }
        if (shares > 0) {
            recipients.push(
                PerformanceFeeRecipient({addr: recipient, shares: shares})
            );
            totalPerformanceFeeShares[bracketIndex] += shares;
        }
    }

    function setGlobalMinDeposit(uint256 newMin) external onlyRole(OWNER_ROLE) {
        globalMinDeposit = newMin;
        emit GlobalMinDepositChanged(newMin);
    }

    function stake(
        uint32 time,
        uint128 amount
    ) external onlyRole(INVESTOR_ROLE) {
        if (amount == 0) revert AmountIsZero();
        if (amount < globalMinDeposit) revert AmountBelowMinimum();
        for (uint i = 0; ; i++) {
            if (i == allowedStakingTimes.length) revert TimeNotAllowed();
            if (allowedStakingTimes[i] == time) break;
        }
        totalStaked += amount;
        uint32 stakeId = _getUniqueStakeId();
        stakes[stakeId] = StakeInfo({
            amount: amount,
            endTime: uint64(block.timestamp + time),
            flags: STAKE_ACTIVE
        });
        token.safeTransferFrom(msg.sender, address(treasury), amount);
        emit Staked(time, stakeId, amount);
    }

    function unstake(uint32 stakeId) external onlyRole(INVESTOR_ROLE) {
        StakeInfo storage stakeInfo = stakes[stakeId];
        if (stakeInfo.flags & STAKE_ACTIVE == 0) revert StakeDoesntExist();
        if (stakeInfo.endTime > block.timestamp) revert StakeNotFinished();
        if (stakeInfo.amount > availableForUnstaking) revert NotEnoughBalance();
        totalStaked -= stakeInfo.amount;
        stakeInfo.flags &= ~STAKE_ACTIVE;
        token.safeTransfer(msg.sender, stakeInfo.amount);
        availableForUnstaking -= stakeInfo.amount;
        emit Unstaked(stakeId, stakeInfo.amount);
    }

    function restake(
        uint32 stakeId,
        uint32 time
    ) external onlyRole(INVESTOR_ROLE) {
        StakeInfo storage stakeInfo = stakes[stakeId];
        if (stakeInfo.flags & STAKE_ACTIVE == 0) revert StakeDoesntExist();
        if (stakeInfo.endTime > block.timestamp) revert StakeNotFinished();
        stakeInfo.flags &= ~STAKE_ACTIVE;
        emit Unstaked(stakeId, stakeInfo.amount);
        if (stakeInfo.amount < globalMinDeposit) revert AmountBelowMinimum();
        for (uint i = 0; ; i++) {
            if (i == allowedStakingTimes.length) revert TimeNotAllowed();
            if (allowedStakingTimes[i] == time) break;
        }
        uint32 newStakeId = _getUniqueStakeId();
        stakes[newStakeId] = StakeInfo({
            amount: stakeInfo.amount,
            endTime: uint64(block.timestamp + time),
            flags: STAKE_ACTIVE
        });
        emit Staked(time, newStakeId, stakeInfo.amount);
    }

    function claimProfit(uint256 amount) external onlyRole(INVESTOR_ROLE) {
        if (amount == 0) amount = profitAvailable;
        if (amount > profitAvailable) revert NotEnoughBalance();
        profitAvailable -= amount;
        token.safeTransfer(msg.sender, amount);
        emit ClaimedProfit(msg.sender, amount);
    }

    function claimPerformanceFee() external {
        uint256 amount = performanceFeeAvailable[msg.sender];
        uint256 balance = token.balanceOf(address(this));
        if (amount > balance) amount = balance;
        performanceFeeAvailable[msg.sender] -= amount;
        token.safeTransfer(msg.sender, amount);
        emit ClaimedPerformanceFee(msg.sender, amount);
    }

    function depositProfit(uint128 amount) external onlyRole(ADMIN_ROLE) {
        require(amount > 0);
        uint256 totalPerformanceFee = 0;
        uint256 prevMax = 0;
        for (uint i = 0; i < performanceFeeBrackets.length; i++) {
            PerformanceFeeBracket storage bracket = performanceFeeBrackets[i];
            uint256 bracketEnd = (totalStaked < bracket.max)
                ? totalStaked
                : bracket.max;
            uint256 range = bracketEnd - prevMax;
            uint256 fractionTimes10k = (range * 10_000) / totalStaked;
            uint256 feeTimes100m = bracket.feeTimes10k * fractionTimes10k;
            uint256 bracketFee = (amount * feeTimes100m) / 100_000_000;
            if (i < performanceFeeRecipients.length) {
                PerformanceFeeRecipient[]
                    storage recipients = performanceFeeRecipients[i];
                uint256 totalShares = totalPerformanceFeeShares[i];
                for (uint j = 0; j < recipients.length; j++) {
                    PerformanceFeeRecipient storage recipient = recipients[j];
                    performanceFeeAvailable[recipient.addr] +=
                        (bracketFee * recipient.shares) /
                        totalShares;
                }
            }
            totalPerformanceFee += bracketFee;
            if (bracket.max >= totalStaked) break;
            prevMax = bracket.max;
        }
        uint256 profit = amount - totalPerformanceFee;
        profitAvailable += profit;
        treasury.withdrawProfit(profit, totalPerformanceFee);
        emit ProfitDeposited(profit, totalPerformanceFee);
    }

    function depositPerformanceFee() external onlyRole(ADMIN_ROLE) {
        uint256 amount = treasury.withdrawPerformanceFees();
        emit PerformanceFeeDeposited(amount);
    }

    function returnStake(uint256 amount) external onlyRole(ADMIN_ROLE) {
        treasury.withdrawStake(amount);
        availableForUnstaking += amount;
        emit StakeReturned(amount);
    }

    function _getUniqueStakeId() private returns (uint32) {
        return nextStakeId++;
    }

    uint256[98] __gap;
}
