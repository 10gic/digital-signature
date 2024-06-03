import { buildEd25519ExpandedPrivateKey, ed25519SignWithExpandedPrivKey } from './ed25519.js';

(async function () {
    const { sr25519Sign, sr25519Verify, sr25519PairFromSeed, cryptoWaitReady } = polkadotUtilCrypto;
    // wait for polkadot crypto to be ready, see: https://github.com/polkadot-js/api/issues/4704
    await cryptoWaitReady();

    const hexToBytes = nobleCurves.utils.hexToBytes // hexToUint8Array
    const bytesToHex = nobleCurves.utils.bytesToHex // uint8ArrayToHex
    const randomBytes = nobleHashes.utils.randomBytes

    const SignType = {
        secp256k1: 'secp256k1',
        secp256r1: 'secp256r1',
        schnorrBip340: 'schnorr-bip340',
        ed25519: 'ed25519',
        sr25519: 'sr25519',
    };

    let privateKeyChangeTimeoutEvent = null
    let inputMessageChangeTimeoutEvent = null

    const DOM = {}
    DOM.signType = $("#signType")
    DOM.generate = $("#generatePrivateKey")
    DOM.privateKey = $("#privateKey")
    DOM.expandedPrivateKeyContainer = $("#expandedPrivateKeyContainer")
    DOM.expandedPrivateKey = $("#expandedPrivateKey")
    DOM.publicKey = $("#publicKey")
    DOM.compressedPublicKeyContainer = $("#compressedPublicKeyContainer")
    DOM.compressedPublicKey = $("#compressedPublicKey")

    DOM.inputMessageType = $("#inputMessageType")
    DOM.inputMessage = $("#inputMessage")
    DOM.schnorrInputMessageTipsContainer = $("#schnorrInputMessageTipsContainer")
    DOM.ed25519InputMessageTipsContainer = $("#ed25519InputMessageTipsContainer")
    DOM.inputMessageHashFuncContainer = $("#inputMessageHashFuncContainer")
    DOM.inputMessageHashFunc = $("#inputMessageHashFunc")
    DOM.inputMessageHashContainer = $("#inputMessageHashContainer")
    DOM.inputMessageHash = $("#inputMessageHash")
    DOM.calculateSign = $("#calculateSign")
    DOM.signResult = $("#signResult")
    DOM.signResultRecoveryIdContainer = $("#signResultRecoveryIdContainer")
    DOM.signResultRecoveryId = $("#signResultRecoveryId")

    DOM.verifySign = $("#verifySign")
    DOM.verifyResult = $("#verifyResult")

    DOM.feedback = $(".feedback")

    function init() {
        // Events
        DOM.signType.on("change", signTypeChanged)
        DOM.generate.on("click", generateClicked)
        DOM.privateKey.on("input", delayedPrivateKeyChanged)
        DOM.inputMessage.on("input", delayedInputMessageChanged)
        DOM.inputMessageHashFunc.on("change", delayedInputMessageChanged)
        DOM.calculateSign.on("click", calculateSignClicked)
        DOM.verifySign.on("click", verifySignClicked)

        disableForms()
        hidePending()
        clearError()
    }

    // Event handlers
    function signTypeChanged(e) {
        // Clear
        DOM.privateKey.val("")
        DOM.expandedPrivateKey.val("")
        DOM.publicKey.val("")
        DOM.compressedPublicKey.val("")

        const signType = e.target.value
        console.log("select", signType)
        if (signType === SignType.secp256k1 || signType === SignType.secp256r1) {
            // No expanded private key for ECDSA
            DOM.expandedPrivateKeyContainer.addClass("hidden")

            // Show compressed public key for ECDSA
            DOM.compressedPublicKeyContainer.removeClass("hidden")

            DOM.schnorrInputMessageTipsContainer.addClass("hidden")
            DOM.ed25519InputMessageTipsContainer.addClass("hidden")

            DOM.inputMessageHashFuncContainer.removeClass("hidden")
            DOM.inputMessageHashContainer.removeClass("hidden")
            DOM.signResultRecoveryIdContainer.removeClass("hidden")
        } else if (signType === SignType.schnorrBip340) {
            // No expanded private key for schnorr
            DOM.expandedPrivateKeyContainer.addClass("hidden")

            // Do not show compressed public key for schnorr
            DOM.compressedPublicKeyContainer.addClass("hidden")

            DOM.schnorrInputMessageTipsContainer.removeClass("hidden")
            DOM.ed25519InputMessageTipsContainer.addClass("hidden")

            DOM.inputMessageHashFuncContainer.addClass("hidden")
            DOM.inputMessageHashContainer.addClass("hidden")
            DOM.signResultRecoveryIdContainer.addClass("hidden")
        } else if (signType === SignType.ed25519) {
            // Show expanded private key
            DOM.expandedPrivateKeyContainer.removeClass("hidden")

            // Do not show compressed public key
            DOM.compressedPublicKeyContainer.addClass("hidden")

            DOM.schnorrInputMessageTipsContainer.addClass("hidden")
            DOM.ed25519InputMessageTipsContainer.removeClass("hidden")

            DOM.inputMessageHashFuncContainer.addClass("hidden")
            DOM.inputMessageHashContainer.addClass("hidden")
            DOM.signResultRecoveryIdContainer.addClass("hidden")
        } else if (signType === SignType.sr25519) {
            // Show expanded private key
            DOM.expandedPrivateKeyContainer.removeClass("hidden")

            // Do not show compressed public key
            DOM.compressedPublicKeyContainer.addClass("hidden")

            DOM.schnorrInputMessageTipsContainer.addClass("hidden")
            DOM.ed25519InputMessageTipsContainer.addClass("hidden")

            DOM.inputMessageHashFuncContainer.addClass("hidden")
            DOM.inputMessageHashContainer.addClass("hidden")
            DOM.signResultRecoveryIdContainer.addClass("hidden")
        } else {
            showError("unreachable code, should not run to here");
        }
    }

    function delayedPrivateKeyChanged() {
        clearError();
        showPending();
        if (privateKeyChangeTimeoutEvent != null) {
            clearTimeout(privateKeyChangeTimeoutEvent);
        }
        privateKeyChangeTimeoutEvent = setTimeout(function () {
            privateKeyChanged();
        }, 400);
    }

    function privateKeyChanged() {
        // Get the privateKey phrase
        const privateKey = DOM.privateKey.val();
        if (privateKey === "") {
            clearError()
            return
        }

        showPending();
        const errorText = findPrivateKeyErrors(privateKey);
        if (errorText) {
            showError(errorText);
            return
        }
        if ((privateKey.startsWith("0x") && privateKey.length !== 66) || (privateKey.length !== 64)) {
            showError("private key must be 64 bytes hex string");
            return
        }

        // Calculate and display
        calcForExpandedPrivateKeyAndPublicKey();
        hidePending();
    }

    async function calcForExpandedPrivateKeyAndPublicKey() {
        // clear it firstly
        DOM.expandedPrivateKey.val("")
        DOM.publicKey.val("")

        const privateKeyUint8Array = hexToBytes(DOM.privateKey.val())
        let publicKeyHex
        let compressedPublicKeyHex

        const signType = DOM.signType.val()
        if (signType === SignType.secp256k1) {
            const publicKey = nobleCurves.secp256k1.getPublicKey(privateKeyUint8Array, false)
            publicKeyHex = bytesToHex(publicKey)

            const compressedPublicKey = nobleCurves.secp256k1.getPublicKey(privateKeyUint8Array, true)
            compressedPublicKeyHex = bytesToHex(compressedPublicKey)
        } else if (signType === SignType.secp256r1) {
            const publicKey = nobleCurves.p256.getPublicKey(privateKeyUint8Array, false)
            publicKeyHex = bytesToHex(publicKey)

            const compressedPublicKey = nobleCurves.p256.getPublicKey(privateKeyUint8Array, true)
            compressedPublicKeyHex = bytesToHex(compressedPublicKey)
        } else if (signType === SignType.schnorrBip340) {
            const publicKey = nobleCurves.secp256k1_schnorr.getPublicKey(privateKeyUint8Array)
            publicKeyHex = bytesToHex(publicKey)
        } else if (signType === SignType.ed25519) {
            const publicKey = nobleCurves.ed25519.getPublicKey(privateKeyUint8Array)
            publicKeyHex = bytesToHex(publicKey)

            const expandedPrivateKey = await buildEd25519ExpandedPrivateKey(privateKeyUint8Array)
            DOM.expandedPrivateKey.val(bytesToHex(expandedPrivateKey))
        } else if (signType === SignType.sr25519) {
            const keypair = sr25519PairFromSeed(privateKeyUint8Array)
            publicKeyHex = bytesToHex(keypair.publicKey)

            const expandedPrivateKey = keypair.secretKey
            if (expandedPrivateKey.length !== 64) {
                throw new Error("expandedPrivateKey length is not 64")
            }

            DOM.expandedPrivateKey.val(bytesToHex(expandedPrivateKey))
        } else {
            console.error("calculateSign, not implementation")
        }

        DOM.publicKey.val(publicKeyHex)
        DOM.compressedPublicKey.val(compressedPublicKeyHex)
    }

    function generateClicked() {
        clearDisplay()
        showPending()
        setTimeout(function () {
            const privateKey = generateRandomPrivateKey()
            if (!privateKey) {
                return
            }
            privateKeyChanged()
        }, 10)
    }

    function generateRandomPrivateKey() {
        const privateKey = randomBytes(32)
        const privateHex = bytesToHex(privateKey)
        DOM.privateKey.val(privateHex)
        return privateHex;
    }

    function delayedInputMessageChanged() {
        clearError();
        if (inputMessageChangeTimeoutEvent != null) {
            clearTimeout(inputMessageChangeTimeoutEvent);
        }
        inputMessageChangeTimeoutEvent = setTimeout(function () {
            inputMessageChanged();
        }, 400);
    }

    function getInputMessage() {
        const inputMessage = DOM.inputMessage.val()
        if (inputMessage === "") {
            return new Uint8Array()
        }

        const inputMessageType = DOM.inputMessageType.val()
        let message
        if (inputMessageType === "utf8") {
            message = new TextEncoder().encode(inputMessage)
        } else if (inputMessageType === "hex") {
            message = hexToBytes(inputMessage)
        } else {
            throw new Error(`invalid input message type ${inputMessageType}`)
        }
        return message
    }

    function inputMessageChanged() {
        const message = getInputMessage()
        if (message === "") {
            return
        }

        const inputMessageHashFunc = DOM.inputMessageHashFunc.val()
        let messageHash
        if (inputMessageHashFunc === "sha256") {
            messageHash = nobleHashes.sha256(message)
        } else if (inputMessageHashFunc === "sha512_256") {
            const result = sha512_256(message) // the function sha512_256 comes from sha512.js
            messageHash = hexToBytes(result)
        } else if (inputMessageHashFunc === "sha3_256") {
            messageHash = nobleHashes.sha3_256(message)
        } else if (inputMessageHashFunc === "keccak_256") {
            messageHash = nobleHashes.keccak_256(message)
        } else if (inputMessageHashFunc === "blake2s_256") {
            messageHash = nobleHashes.blake2s(message)
        } else if (inputMessageHashFunc === "blake2b_256") {
            messageHash = nobleHashes.blake2b(message, {dkLen: 32})
        } else if (inputMessageHashFunc === "blake3_256") {
            messageHash = nobleHashes.blake3(message)
        } else {
            throw new Error(`invalid input message hash func ${inputMessageHashFunc}`)
        }

        console.log(messageHash)
        DOM.inputMessageHash.val(bytesToHex(messageHash))
    }

    function calculateSignClicked() {
        setTimeout(function () {
            calculateSign()
        }, 10)
    }

    function verifySignClicked() {
        setTimeout(function () {
            verifySign()
        }, 10)
    }

    async function calculateSign() {
        clearError()

        // clear sign result firstly
        DOM.signResult.val("")
        DOM.signResultRecoveryId.val("")

        const privateKeyUint8Array = hexToBytes(DOM.privateKey.val())
        let signResult
        let signResultRecoveryId

        const signType = DOM.signType.val()
        if (signType === SignType.secp256k1) {
            if (!privateKeyUint8Array) {
                showError("private key is invalid")
                return
            }

            const inputMessageHashUint8Array = hexToBytes(DOM.inputMessageHash.val())
            if (inputMessageHashUint8Array.length === 0) {
                showError("Input Message Hash is empty")
                return
            }

            signResult = nobleCurves.secp256k1.sign(inputMessageHashUint8Array, privateKeyUint8Array)
            signResultRecoveryId = signResult.recovery // type of number
            signResult = signResult.toCompactRawBytes()

            DOM.signResult.val(bytesToHex(signResult))
            DOM.signResultRecoveryId.val(`0${signResultRecoveryId}`)
        } else if (signType === SignType.secp256r1) {
            if (!privateKeyUint8Array) {
                showError("private key is invalid")
                return
            }

            const inputMessageHashUint8Array = hexToBytes(DOM.inputMessageHash.val())
            if (inputMessageHashUint8Array.length === 0) {
                showError("Input Message Hash is empty")
                return
            }

            signResult = nobleCurves.p256.sign(inputMessageHashUint8Array, privateKeyUint8Array)
            signResultRecoveryId = signResult.recovery // type of number
            signResult = signResult.toCompactRawBytes()

            DOM.signResult.val(bytesToHex(signResult))
            DOM.signResultRecoveryId.val(`0${signResultRecoveryId}`)
        } else if (signType === SignType.schnorrBip340) {
            const inputMessageUint8Array = getInputMessage()
            signResult = nobleCurves.secp256k1_schnorr.sign(inputMessageUint8Array, privateKeyUint8Array)
            DOM.signResult.val(bytesToHex(signResult))
        } else if (signType === SignType.ed25519) {
            const inputMessageUint8Array = getInputMessage()

            if (privateKeyUint8Array) {
                signResult = nobleCurves.ed25519.sign(inputMessageUint8Array, privateKeyUint8Array)
            } else {
                const expandedPrivateKeyUint8Array = hexToBytes(DOM.expandedPrivateKey.val())
                signResult = await ed25519SignWithExpandedPrivKey(inputMessageUint8Array, expandedPrivateKeyUint8Array)
            }
        } else if (signType === SignType.sr25519) {
            let keypair
            if (privateKeyUint8Array) {
                // Just like polkadot, use private key as the seed of sr25519 pair
                // https://github.com/polkadot-js/wasm/blob/4083abb1dd0061c12e689e5b3492ccf0b9a430c7/packages/wasm-crypto/src/rs/sr25519.rs#L88
                keypair = sr25519PairFromSeed(privateKeyUint8Array)
            } else {
                // If private key is not provided, use expanded private key and public key to build a keypair
                //
                // Note: public key certainly can be calculated from expanded private key. However, I don't find such js function
                // So, user must provide public key in such case.
                const expandedPrivateKeyUint8Array = hexToBytes(DOM.expandedPrivateKey.val())
                const publicKeyUint8Array = hexToBytes(DOM.publicKey.val())
                keypair = {
                    secretKey: expandedPrivateKeyUint8Array,
                    publicKey: publicKeyUint8Array,
                }
            }

            const inputMessageUint8Array = getInputMessage()
            signResult = sr25519Sign(inputMessageUint8Array, keypair)
        } else {
            console.error("calculateSign, not implementation")
        }

        DOM.signResult.val(bytesToHex(signResult));
    }

    function verifySign() {
        clearError()

        // clear verify result firstly
        DOM.verifyResult.val("")

        const publicKeyUint8Array = hexToBytes(DOM.publicKey.val())
        const signResultUint8Array = hexToBytes(DOM.signResult.val())
        if (signResultUint8Array.length === 0) {
            showError("Signature Result is empty")
            return
        }
        let verifyResult

        const signType = DOM.signType.val()
        if (signType === SignType.secp256k1) {
            const inputMessageHashUint8Array = hexToBytes(DOM.inputMessageHash.val())
            if (inputMessageHashUint8Array.length === 0) {
                showError("Input Message Hash is empty")
                return
            }

            verifyResult = nobleCurves.secp256k1.verify(signResultUint8Array, inputMessageHashUint8Array, publicKeyUint8Array)
        } else if (signType === SignType.secp256r1) {
            const inputMessageHashUint8Array = hexToBytes(DOM.inputMessageHash.val())
            if (inputMessageHashUint8Array.length === 0) {
                showError("Input Message Hash is empty")
                return
            }

            verifyResult = nobleCurves.p256.verify(signResultUint8Array, inputMessageHashUint8Array, publicKeyUint8Array)
        } else if (signType === SignType.schnorrBip340) {
            const inputMessageUint8Array = getInputMessage()
            verifyResult = nobleCurves.secp256k1_schnorr.verify(signResultUint8Array, inputMessageUint8Array, publicKeyUint8Array)
        } else if (signType === SignType.ed25519) {
            const inputMessageUint8Array = getInputMessage()
            verifyResult = nobleCurves.ed25519.verify(signResultUint8Array, inputMessageUint8Array, publicKeyUint8Array)
        } else if (signType === SignType.sr25519) {
            const inputMessageUint8Array = getInputMessage()
            verifyResult = sr25519Verify(inputMessageUint8Array, signResultUint8Array, publicKeyUint8Array)
        } else {
            showError("unreachable code, should not run to here")
            return
        }

        console.log("verifySign", verifyResult)
        if (verifyResult) {
            DOM.verifyResult.val("Signature is valid. ✅")
        } else {
            DOM.verifyResult.val("Signature is invalid! ❌")
        }
    }

    function showError(errorText) {
        DOM.feedback
            .text(errorText)
            .show();
    }

    function clearError() {
        DOM.feedback
            .text("")
            .hide();
    }

    function findPrivateKeyErrors(privateKey) {
        if (!isHex(privateKey)) {
            return "invalid hex"
        }
        return false;
    }

    function clearDisplay() {
        // clearAddressesList();
        // clearKeys();
        clearError();
    }

    function disableForms() {
        $("form").on("submit", function (e) {
            // See: https://stackoverflow.com/a/7803850
            e.preventDefault();
        });
    }

    function showPending() {
        DOM.feedback
            .text("Calculating...")
            .show();
    }

    function hidePending() {
        DOM.feedback
            .text("")
            .hide();
    }

    function isHex(h) {
        if (h.startsWith("0x")) {
            h = h.slice(2)
        }
        return Boolean(h.match(/^[0-9a-f]+$/i))
    }

    init();

})();
