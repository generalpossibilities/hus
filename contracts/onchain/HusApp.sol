pragma gosh-solidity >=0.76.1;
pragma AbiHeader expire;
pragma AbiHeader pubkey;

contract HusApp {
    string constant version = "2.5.0";

    int256 constant THRESHOLD_SCALED = 5000000;
    uint8 constant MIN_MODALITIES = 2;
    uint8 constant PROJ_DIM = 128;
    uint8 constant MIN_SCORE = 80;

    struct Registration {
        bytes32 commitmentHash;
        int64[] vObf;
        uint8 modalityId;
        uint32 timestamp;
        bytes proof;
    }

    struct ModalityConfig {
        uint8 modalityId;
        uint8 projDim;
        uint8 minScore;
    }

    address public static husRegistry;
    uint256 public static appId;

    bytes private _vk;
    uint256 private _seedHash;
    uint32 private _appVersion;
    uint32 private _registrationCount;
    mapping(uint256 => bool) private _seenCommitments;
    Registration[] private _registrations;

    ModalityConfig[] private _modalityConfigList;
    mapping(uint8 => ModalityConfig) private _modalityConfigMap;

    event UniquenessResult(
        uint256 indexed appId,
        bool isUnique,
        uint8 score,
        uint8 modalityId
    );

    event DepositConfirmed(
        uint256 indexed paymentId,
        uint256 amount
    );

    event UpgradeExecuted(uint32 newVersion);
    event VkUpdated();

    // ── Constructor ─────────────────────────────────────────────

    constructor(
        bytes vk,
        uint256 seedHash,
        uint8[] modalityIds
    ) {
        tvm.accept();
        require(modalityIds.length >= MIN_MODALITIES, 104);
        _vk = vk;
        _seedHash = seedHash;
        _appVersion = 1;
        _registrationCount = 0;
        for (uint8 i = 0; i < modalityIds.length; i++) {
            uint8 mid = modalityIds[i];
            require(_modalityConfigMap[mid].projDim == 0, 107);
            _modalityConfigMap[mid] = ModalityConfig(mid, PROJ_DIM, MIN_SCORE);
            _modalityConfigList.push(ModalityConfig(mid, PROJ_DIM, MIN_SCORE));
        }
    }

    // ── Registry-controlled upgrade ─────────────────────────────

    function upgradeCode(TvmCell newCode, bytes newVk) external {
        tvm.accept();
        require(msg.sender == husRegistry, 200);
        require(newCode.toSlice().bits() != 0, 201);

        _vk = newVk;
        _appVersion++;

        tvm.setcode(newCode);
        tvm.setCurrentCode(newCode);

        emit UpgradeExecuted(_appVersion);
    }

    function setVk(bytes newVk) external {
        tvm.accept();
        require(msg.sender == husRegistry, 200);
        _vk = newVk;
        emit VkUpdated();
    }

    // ── Deposit ─────────────────────────────────────────────────

    function deposit(uint256 paymentId) external {
        require(msg.value > 0, 202);
        tvm.accept();
        gosh.cnvrtshellq(uint64(msg.value));
        emit DepositConfirmed(paymentId, address(this).balance);
    }

    // ── Submission methods ─────────────────────────────────────

    function submitWithProof(
        int64[] vObf,
        bytes proof,
        bytes commitment,
        uint8 modalityId
    ) external returns (bool isUnique, uint8 score) {
        tvm.accept();

        _assertModalityConfig(modalityId, uint32(vObf.length));

        bool proofOk = gosh.vergrth16(commitment, proof);
        require(proofOk, 130);

        (isUnique, score) = _register(tvm.hash(commitment), vObf, proof, modalityId);
    }

    function submitCommitment(
        bytes32 commitmentHash,
        int64[] vObf,
        uint8 modalityId
    ) external returns (bool isUnique, uint8 score) {
        tvm.accept();

        _assertModalityConfig(modalityId, uint32(vObf.length));

        uint256 commKey = uint256(commitmentHash);
        require(!_seenCommitments[commKey], 114);

        (isUnique, score) = _registerInternal(uint256(commitmentHash), vObf, modalityId);
    }

    // ── Internal ──────────────────────────────────────────────

    function _register(
        uint256 commKey,
        int64[] vObf,
        bytes proof,
        uint8 modalityId
    ) internal returns (bool isUnique, uint8 score) {
        require(!_seenCommitments[commKey], 114);

        int256 minDist = type(int256).max;
        uint32 n = _registrationCount;
        for (uint32 i = 0; i < n; i++) {
            if (_registrations[i].modalityId == modalityId) {
                int256 dist = _l2Distance(vObf, _registrations[i].vObf);
                if (dist < minDist) {
                    minDist = dist;
                }
            }
        }

        if (minDist == type(int256).max) {
            score = 100;
        } else {
            score = _calculateScore(minDist);
        }

        ModalityConfig cfg = _modalityConfigMap[modalityId];
        isUnique = (minDist == type(int256).max) || (score < cfg.minScore);

        if (isUnique) {
            Registration r;
            r.commitmentHash = bytes32(commKey);
            r.modalityId = modalityId;
            r.timestamp = uint32(block.timestamp);
            r.proof = proof;
            uint32 vlen = uint32(vObf.length);
            for (uint32 j = 0; j < vlen; j++) {
                r.vObf.push(vObf[j]);
            }
            _seenCommitments[commKey] = true;
            _registrations.push(r);
            _registrationCount = n + 1;
        }

        emit UniquenessResult(appId, isUnique, score, modalityId);
        return (isUnique, score);
    }

    function _registerInternal(
        uint256 commKey,
        int64[] vObf,
        uint8 modalityId
    ) internal returns (bool isUnique, uint8 score) {
        return _register(commKey, vObf, "", modalityId);
    }

    function _assertModalityConfig(uint8 modalityId, uint32 vObfLen) internal view {
        ModalityConfig c = _modalityConfigMap[modalityId];
        require(c.projDim > 0, 131);
        require(vObfLen == uint32(c.projDim), 132);
    }

    function _l2Distance(int64[] a, int64[] b)
        internal pure returns (int256)
    {
        require(a.length == b.length, 150);
        int256 sumSq = 0;
        for (uint32 i = 0; i < a.length; i++) {
            int256 diff = int256(a[i]) - int256(b[i]);
            sumSq += diff * diff;
        }
        return _isqrt(sumSq);
    }

    function _isqrt(int256 x) internal pure returns (int256) {
        if (x <= 0) return 0;
        uint256 ux = uint256(x);
        if (ux < 2) return int256(ux);
        uint256 z = (ux + 1) / 2;
        uint256 y = ux;
        while (z < y) {
            y = z;
            z = (ux / z + z) / 2;
        }
        return int256(y);
    }

    function _calculateScore(int256 dist) internal pure returns (uint8) {
        require(dist >= 0, "distance must be non-negative");
        if (dist >= THRESHOLD_SCALED) return 0;
        uint256 num = uint256(THRESHOLD_SCALED - dist) * 100;
        uint256 raw = num / uint256(THRESHOLD_SCALED);
        if (raw > 100) return 100;
        return uint8(raw);
    }

    // ── View functions ────────────────────────────────────────

    function checkDuplicate(bytes32 commitmentHash) external view returns (bool) {
        return _seenCommitments[uint256(commitmentHash)];
    }

    function getRegistration(uint32 index) external view returns (
        bytes32 commitmentHash,
        int64[] vObf,
        uint8 modalityId,
        uint32 timestamp,
        bytes proof
    ) {
        require(index < _registrationCount, 120);
        Registration r = _registrations[index];
        return (r.commitmentHash, r.vObf, r.modalityId, r.timestamp, r.proof);
    }

    function getRegistrationCount() external view returns (uint32) {
        return _registrationCount;
    }

    function getAppInfo() external view returns (
        bytes vk,
        uint32 appVersion,
        uint256 seedHash,
        uint32 registrationCount
    ) {
        return (_vk, _appVersion, _seedHash, _registrationCount);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function getModalityConfigs() external view returns (ModalityConfig[]) {
        return _modalityConfigList;
    }

    function getModalityConfig(uint8 modalityId) external view returns (ModalityConfig) {
        ModalityConfig c = _modalityConfigMap[modalityId];
        require(c.projDim > 0, 131);
        return c;
    }

    function getVersion() external pure returns (string) {
        return version;
    }

    function getVerificationFee() external pure returns (uint256) {
        return 300000000;
    }
}
