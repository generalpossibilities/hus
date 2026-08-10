pragma gosh-solidity >=0.76.1;
pragma AbiHeader expire;
pragma AbiHeader pubkey;

import "./HusApp.sol";

contract HusRegistry {
    string constant version = "2.4.2";

    uint32 constant UPGRADE_DELAY = 604800;

    TvmCell private _appCode;
    bytes private _provingKey;
    bytes private _vk;

    uint256 private _ownerPubkey;
    mapping(uint256 => address) private _appRegistry;

    struct PendingUpgrade {
        TvmCell newCode;
        bytes newVk;
        uint32 proposedAt;
    }
    mapping(uint256 => PendingUpgrade) private _pendingUpgrades;

    // Chunked proving key storage (for large PKs that don't fit in one message)
    mapping(uint16 => bytes) private _provingKeyChunks;
    uint16 private _provingKeyChunkCount;
    uint256 private _provingKeyHash;

    event AppRegistered(
        uint256 indexed appId,
        address indexed appAddress
    );

    event ProvingKeySet();
    event VkSet();
    event AppUpgradeProposed(
        uint256 indexed appId,
        uint32 proposedAt,
        uint32 executeAt
    );
    event AppUpgradeCancelled(uint256 indexed appId);
    event AppUpgradeExecuted(uint256 indexed appId);

    // ── Constructor ────────────────────────────────────────────

    constructor(TvmCell appCode) {
        tvm.accept();
        _appCode = appCode;
        _ownerPubkey = msg.pubkey();
    }

    // ── Admin (owner-only) ─────────────────────────────────────

    modifier onlyOwner() {
        require(msg.pubkey() == _ownerPubkey, 101);
        _;
    }

    function setProvingKey(bytes pk) external onlyOwner {
        tvm.accept();
        _provingKey = pk;
        emit ProvingKeySet();
    }

    function setVk(bytes vk) external onlyOwner {
        tvm.accept();
        _vk = vk;
        emit VkSet();
    }

    // ── Chunked proving key storage (for large PKs) ──────────

    function setProvingKeyChunk(uint16 index, bytes chunk) external onlyOwner {
        tvm.accept();
        require(chunk.length > 0, 120);
        _provingKeyChunks[index] = chunk;
        if (index >= _provingKeyChunkCount) {
            _provingKeyChunkCount = index + 1;
        }
    }

    function clearProvingKeyChunks() external onlyOwner {
        tvm.accept();
        _provingKeyChunkCount = 0;
        _provingKeyHash = 0;
    }

    function setProvingKeyHash(uint256 hash) external onlyOwner {
        tvm.accept();
        _provingKeyHash = hash;
    }

    // ── App management (permissionless) ───────────────────────

    function registerApp(
        string appName,
        uint8[] modalityIds
    ) external returns (address appAddress) {
        tvm.accept();
        require(_appCode.toSlice().bits() != 0, 102);
        require(modalityIds.length >= 2, 104);

        uint256 callerPubkey = msg.pubkey();
        if (callerPubkey == 0) {
            callerPubkey = _ownerPubkey;
        }
        TvmBuilder b;
        b.store(callerPubkey);
        b.store(appName);
        uint256 appId = uint256(tvm.hash(b.toCell()));
        require(!_appRegistry.exists(appId), 103);

        TvmBuilder b2;
        b2.store(callerPubkey);
        b2.store(appId);
        b2.store(block.timestamp);
        uint256 seedHash = uint256(sha256(b2.toCell().toSlice()));

        TvmCell stateInit = abi.encodeStateInit({
            code: _appCode,
            contr: HusApp,
            varInit: {husRegistry: address(this), appId: appId}
        });
        address appAddr = new HusApp{
            stateInit: stateInit,
            value: 0.3 vmshell,
            flag: 1,
            wid: 0
        }(_vk, seedHash, modalityIds);

        _appRegistry[appId] = appAddr;

        emit AppRegistered(appId, appAddr);
        return appAddr;
    }

    // ── Timelocked upgrade mechanism ──────────────────────────

    function proposeAppUpgrade(
        uint256 appId,
        TvmCell newCode,
        bytes newVk
    ) external onlyOwner {
        tvm.accept();
        require(_appRegistry.exists(appId), 110);
        require(newCode.toSlice().bits() != 0, 111);

        uint32 proposedAt = uint32(block.timestamp);
        _pendingUpgrades[appId] = PendingUpgrade(newCode, newVk, proposedAt);

        uint32 executeAt = proposedAt + UPGRADE_DELAY;
        emit AppUpgradeProposed(appId, proposedAt, executeAt);
    }

    function cancelAppUpgrade(uint256 appId) external onlyOwner {
        tvm.accept();
        require(_pendingUpgrades.exists(appId), 112);
        delete _pendingUpgrades[appId];
        emit AppUpgradeCancelled(appId);
    }

    function executeAppUpgrade(uint256 appId) external {
        tvm.accept();
        require(_pendingUpgrades.exists(appId), 112);

        require(uint32(block.timestamp) >= _pendingUpgrades[appId].proposedAt + UPGRADE_DELAY, 113);

        address appAddr = _appRegistry[appId];
        HusApp(appAddr).upgradeCode{value: 0.05 vmshell, flag: 1}(
            _pendingUpgrades[appId].newCode,
            _pendingUpgrades[appId].newVk
        );

        delete _pendingUpgrades[appId];
        emit AppUpgradeExecuted(appId);
    }

    // ── View functions ────────────────────────────────────────

    function getAppAddress(uint256 appId) external view returns (address) {
        return _appRegistry[appId];
    }

    function isAppRegistered(uint256 appId) external view returns (bool) {
        return _appRegistry.exists(appId);
    }

    function getProvingKey() external view returns (bytes) {
        return _provingKey;
    }

    function getVk() external view returns (bytes) {
        return _vk;
    }

    function getUpgradeDelay() external pure returns (uint32) {
        return UPGRADE_DELAY;
    }

    function getPendingUpgrade(uint256 appId)
        external view returns (TvmCell newCode, bytes newVk, uint32 proposedAt)
    {
        require(_pendingUpgrades.exists(appId), 112);
        return (
            _pendingUpgrades[appId].newCode,
            _pendingUpgrades[appId].newVk,
            _pendingUpgrades[appId].proposedAt
        );
    }

    function isUpgradeReady(uint256 appId) external view returns (bool) {
        if (!_pendingUpgrades.exists(appId)) return false;
        return uint32(block.timestamp) >= _pendingUpgrades[appId].proposedAt + UPGRADE_DELAY;
    }

    function getProvingKeyChunkCount() external view returns (uint16) {
        return _provingKeyChunkCount;
    }

    function getProvingKeyChunk(uint16 index) external view returns (bytes) {
        require(index < _provingKeyChunkCount, 121);
        return _provingKeyChunks[index];
    }

    function getProvingKeyHash() external view returns (uint256) {
        return _provingKeyHash;
    }

    function getVersion() external pure returns (string) {
        return version;
    }
}
