package li.power.app.fido.nfcpasskey

import android.app.Activity
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import de.cotech.hw.SecurityKeyManager
import de.cotech.hw.SecurityKeyManagerConfig
import de.cotech.hw.fido2.PublicKeyCredential
import de.cotech.hw.fido2.PublicKeyCredentialCreate
import de.cotech.hw.fido2.PublicKeyCredentialGet
import de.cotech.hw.fido2.internal.cbor_java.CborDecoder
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString
import de.cotech.hw.fido2.internal.cbor_java.model.Map
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString
import de.cotech.hw.fido2.internal.cose.CoseIdentifiers
import de.cotech.hw.fido2.internal.json.JsonPublicKeyCredentialSerializer
import de.cotech.hw.fido2.internal.json.JsonWebauthnOptionsParser
import de.cotech.hw.fido2.internal.webauthn.AuthenticatorDataParser
import de.cotech.hw.fido2.ui.WebauthnDialogFragment
import li.power.app.fido.nfcpasskey.service.ACTION_CREATE_PASSKEY
import li.power.app.fido.nfcpasskey.service.ACTION_GET_PASSKEY
import li.power.app.fido.nfcpasskey.service.EXTRA_TOKEN_ID
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyFactory
import java.security.Security
import kotlin.io.encoding.ExperimentalEncodingApi

class PasskeyActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_passkey)
        setupBouncyCastle()

        if (intent != null) {
            val accountId = intent.getStringExtra(EXTRA_TOKEN_ID)

            val securityKeyManager = SecurityKeyManager.getInstance()
            val config = SecurityKeyManagerConfig.Builder()
                .setEnableDebugLogging(true)
                .build()
            if (!securityKeyManager.initialized()) {
                securityKeyManager.init(application, config)
            }

            if (intent.action.equals(ACTION_CREATE_PASSKEY)) {
                val request =
                    PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
                if (request != null) {
                    val publicKeyRequest: CreatePublicKeyCredentialRequest =
                        request.callingRequest as CreatePublicKeyCredentialRequest
                    publicKeyRequest.origin?.let { showRegisterDialog(it, publicKeyRequest.requestJson) }
                }
            } else if (intent.action.equals(ACTION_GET_PASSKEY)) {
                val request =
                    PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
                val publicKeyRequests =
                    request!!.credentialOptions as List<GetPublicKeyCredentialOption>

                val requestInfo = intent.getBundleExtra("CREDENTIAL_DATA")

                publicKeyRequests.forEach { credentialOption ->
                    Log.d("NFCPK", "requsetJson:${credentialOption.requestJson}")
                }
            }
        }

    }

    private fun showRegisterDialog(origin: String, json: String) {
        val jo = JSONObject()
        jo.put("publicKey", JSONObject(json))
        Log.d("NFCPK", jo.toString())
        val dialogFragment = WebauthnDialogFragment.newInstance(
            PublicKeyCredentialCreate.create(
                origin,
                JsonWebauthnOptionsParser().fromOptionsJsonMakeCredential(jo.toString())
            )
        )
        dialogFragment.setOnMakeCredentialCallback(onMakeCredentialCallback)
        dialogFragment.show(supportFragmentManager)
    }

    private fun showAuthenticateDialog(origin: String, json: String) {
        val jo = JSONObject()
        jo.put("publicKey", JSONObject(json))
        Log.d("NFCPK", jo.toString())
        val dialogFragment = WebauthnDialogFragment.newInstance(
            PublicKeyCredentialGet.create(
                origin,
                JsonWebauthnOptionsParser().fromOptionsJsonGetAssertion(jo.toString())
            )
        )
        dialogFragment.setOnGetAssertionCallback(onGetAssertionCallback)

        dialogFragment.show(supportFragmentManager)
    }

    private fun processPublicKeyCredential(publicKeyCredential: PublicKeyCredential) {
        val result = Intent()
        val jo = JSONObject(JsonPublicKeyCredentialSerializer().publicKeyCredentialToJsonString(publicKeyCredential))
        Log.d("NFCPK", "Before: $jo")
        jo.put("rawId", publicKeyCredential.id())
        val dataItems = CborDecoder.decode(
            Base64.decode(
                jo.getJSONObject("response").getString("attestationObject"),
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
        )
        var map = dataItems[0] as Map
        val authDataBytes = map[UnicodeString("authData")] as ByteString

        val authData = AuthenticatorDataParser().fromBytes(authDataBytes.bytes)

        val response = jo.getJSONObject("response")
        response.put("publicKeyAlgorithm", -7)
        val publicKeyItems = CborDecoder.decode(authData.attestedCredentialData()?.credentialPublicKey())
        map = publicKeyItems[0] as Map
        val x = map[CoseIdentifiers.X] as ByteString
        val y = map[CoseIdentifiers.Y] as ByteString
        val publicKey = ByteArray(65)
        System.arraycopy(x.bytes, 0, publicKey, 1, 32)
        System.arraycopy(y.bytes, 0, publicKey, 33, 32)
        publicKey[0] = 0x04

        val params = ECNamedCurveTable.getParameterSpec("secp256r1")
        val pubKeySpec = ECPublicKeySpec(
            params.curve.decodePoint(publicKey), params
        )
        val kf: KeyFactory = KeyFactory.getInstance("ECDH", "BC")

        response.put("publicKey", b64Encode(kf.generatePublic(pubKeySpec).encoded))
        response.put("authenticatorData", b64Encode(authDataBytes.bytes))
        response.putOpt("transports", JSONArray().put("hybrid"))
        jo.put("authenticatorAttachment", "cross-platform")
        jo.put("clientExtensionResults", JSONObject())
        jo.put("response", response)

        Log.d("NFCPK", "After: $jo")

        PendingIntentHandler.setCreateCredentialResponse(
            result, CreatePublicKeyCredentialResponse(jo.toString())
        )

        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private val onGetAssertionCallback = object : WebauthnDialogFragment.OnGetAssertionCallback {
        override fun onGetAssertionCancel() {
            super.onGetAssertionCancel()
            finish()
        }

        override fun onGetAssertionTimeout() {
            super.onGetAssertionTimeout()
            finish()
        }

        override fun onGetAssertionResponse(publicKeyCredential: PublicKeyCredential) {
            processPublicKeyCredential(publicKeyCredential)
        }
    }

    private val onMakeCredentialCallback = object : WebauthnDialogFragment.OnMakeCredentialCallback {
        override fun onMakeCredentialResponse(publicKeyCredential: PublicKeyCredential) {
            processPublicKeyCredential(publicKeyCredential)
        }

        override fun onMakeCredentialCancel() {
            super.onMakeCredentialCancel()
            finish()
        }

        override fun onMakeCredentialTimeout() {
            super.onMakeCredentialTimeout()
            finish()
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun b64Encode(data: ByteArray): String {
        // replace with import androidx.credentials.webauthn.WebAuthnUtils in future
        return kotlin.io.encoding.Base64.UrlSafe.encode(data).replace("=", "")
    }


    private fun setupBouncyCastle() {
        val provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
        if (provider == null) {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
        if (provider.javaClass == BouncyCastleProvider::class.java) {
            return
        }
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }


}