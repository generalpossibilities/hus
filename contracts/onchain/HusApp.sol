pragma gosh-solidity >=0.76.1;
pragma AbiHeader expire;
pragma AbiHeader pubkey;

contract HusApp {
    string constant version = "2.7.0";

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
        // Who the proof was made for: proof_binding(owner key, challenge),
        // the circuit's last public input. Needed to re-check the proof.
        uint256 binding;
        // SHA-256 of the hardware attestation (the device's certificate
        // chain) the verifier checked. The chain itself is published by the
        // verifier, so anyone can re-check it against this hash.
        uint256 attestationHash;
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
    // The app operator's key, and the key of the verifier that checks proofs
    // off-chain and is the only one allowed to register (see submitVerified).
    uint256 private _ownerPubkey;
    uint256 private _verifierPubkey;
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
    event VerifierUpdated(uint256 verifierPubkey);

    // ── Constructor ─────────────────────────────────────────────

    constructor(
        bytes vk,
        uint256 seedHash,
        uint8[] modalityIds,
        uint256 ownerPubkey
    ) {
        require(msg.sender == husRegistry, 200);
        require(ownerPubkey != 0, 108);
        require(modalityIds.length >= MIN_MODALITIES, 104);
        tvm.accept();
        _vk = vk;
        _seedHash = seedHash;
        _ownerPubkey = ownerPubkey;
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

    // Checks come before tvm.accept(): an external message that fails a check
    // must not be paid for by the contract.
    function upgradeCode(TvmCell newCode, bytes newVk) external {
        require(msg.sender == husRegistry, 200);
        require(newCode.toSlice().bits() != 0, 201);
        tvm.accept();

        _vk = newVk;
        _appVersion++;

        tvm.setcode(newCode);
        tvm.setCurrentCode(newCode);

        emit UpgradeExecuted(_appVersion);
    }

    function setVk(bytes newVk) external {
        require(msg.sender == husRegistry, 200);
        tvm.accept();
        _vk = newVk;
        emit VkUpdated();
    }

    /// The operator names the verifier key. Zero turns registration off.
    function setVerifier(uint256 verifierPubkey) external {
        require(msg.pubkey() == _ownerPubkey, 101);
        tvm.accept();
        _verifierPubkey = verifierPubkey;
        emit VerifierUpdated(verifierPubkey);
    }

    // ── Deposit ─────────────────────────────────────────────────

    function deposit(uint256 paymentId) external {
        require(msg.value > 0, 202);
        tvm.accept();
        gosh.cnvrtshellq(uint64(msg.value));
        emit DepositConfirmed(paymentId, address(this).balance);
    }

    // ── Submission methods ─────────────────────────────────────

    // Hybrid verification. TVM's gosh.vergrth16 only accepts the network's
    // built-in (ZkLogin) verifying keys, not this circuit's, so the proof can't
    // be checked here. The app's verifier checks it off-chain against all the
    // public inputs (commitment and every vObf element) and signs this call;
    // nobody else can register. The proof is stored so anyone can re-check it
    // against the stored vObf. On-chain verification lives in the AVM
    // verifier (avm/groth16-avm) for networks that can run it.
    //
    // The old submitWithProof (claimed an on-chain check it couldn't make) and
    // submitCommitment (no proof, anyone) are gone.
    function submitVerified(
        bytes32 commitmentHash,
        int64[] vObf,
        bytes proof,
        uint256 binding,
        uint256 attestationHash,
        uint8 modalityId
    ) external returns (bool isUnique, uint8 score) {
        require(_verifierPubkey != 0 && msg.pubkey() == _verifierPubkey, 109);
        require(proof.length > 0, 133);
        require(attestationHash != 0, 134);
        _assertModalityConfig(modalityId, uint32(vObf.length));
        require(!_seenCommitments[uint256(commitmentHash)], 114);
        tvm.accept();

        (isUnique, score) = _register(uint256(commitmentHash), vObf, proof, binding, attestationHash, modalityId);
    }

    // ── Internal ──────────────────────────────────────────────

    function _register(
        uint256 commKey,
        int64[] vObf,
        bytes proof,
        uint256 binding,
        uint256 attestationHash,
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
            r.binding = binding;
            r.attestationHash = attestationHash;
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
        bytes proof,
        uint256 binding,
        uint256 attestationHash
    ) {
        require(index < _registrationCount, 120);
        Registration r = _registrations[index];
        return (r.commitmentHash, r.vObf, r.modalityId, r.timestamp, r.proof, r.binding, r.attestationHash);
    }

    function getRegistrationCount() external view returns (uint32) {
        return _registrationCount;
    }

    function getVerifier() external view returns (uint256) {
        return _verifierPubkey;
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
