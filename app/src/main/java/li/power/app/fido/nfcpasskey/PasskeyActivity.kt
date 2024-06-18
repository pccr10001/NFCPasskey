package li.power.app.fido.nfcpasskey

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.webauthn.*
import com.google.gson.Gson
import de.cotech.hw.SecurityKeyManager
import de.cotech.hw.SecurityKeyManagerConfig
import de.cotech.hw.fido2.PublicKeyCredential
import de.cotech.hw.fido2.PublicKeyCredentialCreate
import de.cotech.hw.fido2.PublicKeyCredentialGet
import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor
import de.cotech.hw.fido2.internal.cbor_java.CborDecoder
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString
import de.cotech.hw.fido2.internal.cbor_java.model.Map
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString
import de.cotech.hw.fido2.internal.cose.CoseIdentifiers
import de.cotech.hw.fido2.internal.json.JsonCollectedClientDataSerializer
import de.cotech.hw.fido2.internal.json.JsonPublicKeyCredentialSerializer
import de.cotech.hw.fido2.internal.json.JsonWebauthnOptionsParser
import de.cotech.hw.fido2.internal.webauthn.AuthenticatorDataParser
import de.cotech.hw.fido2.ui.WebauthnDialogFragment
import de.cotech.hw.internal.HwSentry
import li.power.app.fido.nfcpasskey.model.AppDatabase
import li.power.app.fido.nfcpasskey.model.Credential
import li.power.app.fido.nfcpasskey.service.ACTION_CREATE_PASSKEY
import li.power.app.fido.nfcpasskey.service.ACTION_GET_PASSKEY
import li.power.app.fido.nfcpasskey.service.EXTRA_TOKEN_ID
import org.apache.commons.lang3.StringEscapeUtils
import org.apache.commons.lang3.StringUtils
import org.bouncycastle.jcajce.provider.symmetric.ARC4.Base
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.json.JSONArray
import org.json.JSONObject
import java.io.UnsupportedEncodingException
import java.net.URI
import java.security.KeyFactory
import java.security.Security
import kotlin.experimental.and
import kotlin.io.encoding.ExperimentalEncodingApi

class PasskeyActivity : AppCompatActivity() {

    var authenticatorType = "Cross-Platform"
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_passkey)
        setupBouncyCastle()

        if (intent != null) {
            val accountId = intent.getStringExtra(EXTRA_TOKEN_ID)

            val securityKeyManager = SecurityKeyManager.getInstance()
            val config = SecurityKeyManagerConfig.Builder()
                .setEnableDebugLogging(true)
                .setSentrySupportDisabled(false)
                .build()
            if (!securityKeyManager.initialized()) {
                securityKeyManager.init(application, config)
            }

            if (intent.action.equals(ACTION_CREATE_PASSKEY)) {
                authenticatorType = intent.getStringExtra(EXTRA_TOKEN_ID)!!
                val request =
                    PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
                if (request != null) {
                    val publicKeyRequest: CreatePublicKeyCredentialRequest =
                        request.callingRequest as CreatePublicKeyCredentialRequest

                    showRegisterDialog(request.callingAppInfo.origin, publicKeyRequest.requestJson)
                }
            } else if (intent.action.equals(ACTION_GET_PASSKEY)) {
                authenticatorType = intent.getStringExtra("type")!!
                val request =
                    PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
                if (request != null) {
                    val publicKeyRequests =
                        request.credentialOptions as List<GetPublicKeyCredentialOption>
                    showAuthenticateDialog(request.callingAppInfo.origin, publicKeyRequests[0].requestJson, publicKeyRequests[0].clientDataHash)
                }
            }
        }
    }

    private fun showRegisterDialog(origin: String?, json: String) {
        val jo = JSONObject()
        jo.put("publicKey", JSONObject(json))
        Log.d("NFCPK", jo.toString())

        val option = JsonWebauthnOptionsParser().fromOptionsJsonMakeCredential(jo.toString())
        Log.d("NFCPK", Gson().toJson(option))
        if(origin == null) {
            val dialogFragment = WebauthnDialogFragment.newInstance(
                PublicKeyCredentialCreate.create(
                    "https://" + option.rp().id(),
                    option
                )
            )
            dialogFragment.setOnMakeCredentialCallback(onMakeCredentialCallback)
            dialogFragment.show(supportFragmentManager)
            return
        }
            val dialogFragment = WebauthnDialogFragment.newInstance(
                PublicKeyCredentialCreate.create(
                    origin,
                    option
                )
            )
            dialogFragment.setOnMakeCredentialCallback(onMakeCredentialCallback)
            dialogFragment.show(supportFragmentManager)


    }

    private fun showAuthenticateDialog(origin: String?, json: String, clientDataHash: ByteArray?) {
        val jo = JSONObject()
        Log.d("NFCPK",json)
        val request = JSONObject(json)
        request.putOpt(
            "challenge",
            JSONArray(
                Base64.decode(
                    request.getString("challenge"),
                    Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE
                )
            )
        )
        jo.put("publicKey", request)

        val option = JsonWebauthnOptionsParser().fromOptionsJsonGetAssertion(jo.toString())
        if(option.allowCredentials()!= null) {
            val allowCredentials = ArrayList<PublicKeyCredentialDescriptor>()
            for (ac in option.allowCredentials()!!) {
                allowCredentials.add(
                    PublicKeyCredentialDescriptor.create(
                        ac.type(),
                        Base64.decode(ac.id(), Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING),
                        ac.transports()
                    )
                )
            }
            option.allowCredentials()!!.clear()
            option.allowCredentials()!!.addAll(allowCredentials)
        }

        Log.d("NFCPK", Gson().toJson(option))

        if(origin == null){

            val dialogFragment = WebauthnDialogFragment.newInstance(
                PublicKeyCredentialGet.create(
                    "https://" + option.rpId(),
                    option,
                    clientDataHash,
                )
            )

            dialogFragment.setOnGetAssertionCallback(onGetAssertionCallback)
            dialogFragment.show(supportFragmentManager)
            return
        }
        val dialogFragment = WebauthnDialogFragment.newInstance(
            PublicKeyCredentialGet.create(
                origin,
                option,
                clientDataHash,
            )
        )

        dialogFragment.setOnGetAssertionCallback(onGetAssertionCallback)
        dialogFragment.show(supportFragmentManager)
    }

    private fun processCreateCredential(publicKeyCredential: PublicKeyCredential) {
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
        response.putOpt("transports", JSONArray().put("nfc"))
        jo.put("authenticatorAttachment", "cross-platform")
        jo.put("clientExtensionResults", JSONObject())
        jo.put("response", response)

        Log.d("NFCPK", "After: $jo")

        PendingIntentHandler.setCreateCredentialResponse(
            result, CreatePublicKeyCredentialResponse(jo.toString())
        )

        var credentialDao = AppDatabase.getDatabase(this).credentialDao
        var credId = publicKeyCredential.id()
        val request =
            PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val publicKeyRequest = request?.callingRequest as CreatePublicKeyCredentialRequest

        val option = PublicKeyCredentialCreationOptions(publicKeyRequest.requestJson)

        val credential = Credential(
            credId,
            option.rp.id,
            option.rp.name,
            String(option.user.id),
            option.user.name,
            b64Encode(kf.generatePublic(pubKeySpec).encoded),
            ""
        )

        if (SecurityKeyManager.getLastTagId().isNotEmpty()) {
            credential.tokenId = SecurityKeyManager.getLastTagId()
        }

        credentialDao.insertAll(credential)
        Log.d("NFCPK", Gson().toJson(credential))
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private class ExternalAuthenticatorResponse(
        override var clientJson: JSONObject,
        private val clientJsonString: String,
        private val clientDataHash: ByteArray,
        private val authenticatorData: ByteArray,
        private val signature: ByteArray,
        private val userHandle: ByteArray
    ) :
        AuthenticatorResponse {
        override fun json(): JSONObject {
            var response = JSONObject()
            response.put("clientDataJSON", clientJsonString)
            response.put("clientDataHash", JSONArray(clientDataHash))
            response.put(
                "authenticatorData",
                Base64.encodeToString(authenticatorData, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            )
            response.put(
                "signature",
                Base64.encodeToString(signature, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            )
            response.put(
                "userHandle",
                Base64.encodeToString(userHandle, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            )
            return response
        }
    }

    private fun processGetCredential(publicKeyCredential: PublicKeyCredential) {
        val requestIntent =
            PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val publicKeyRequests =
            requestIntent!!.credentialOptions as List<GetPublicKeyCredentialOption>

        val jo = JSONObject(JsonPublicKeyCredentialSerializer().publicKeyCredentialToJsonString(publicKeyCredential))

        Log.d("NFCPK", jo.toString())
        val authDataBytes = b64Decode(jo.getJSONObject("response").getString("authenticatorData"))

        var userHandle = ByteArray(0)

        if (jo.getJSONObject("response").has("userHandle")) {
            userHandle = b64Decode(jo.getJSONObject("response").getString("userHandle"))
        }


        val credential = FidoPublicKeyCredential(
            rawId = publicKeyCredential.rawId(),
            response = ExternalAuthenticatorResponse(
                JSONObject(),
                jo.getJSONObject("response").getString("clientDataJson"),
                publicKeyRequests[0].clientDataHash!!,
                authDataBytes,
                Base64.decode(
                    jo.getJSONObject("response").getString("signature"),
                    Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                ),
                userHandle,
            ),
            authenticatorAttachment = authenticatorType
        )
        val result = Intent()
        val passkeyCredential = androidx.credentials.PublicKeyCredential(credential.json())
        PendingIntentHandler.setGetCredentialResponse(
            result, GetCredentialResponse(passkeyCredential)
        )
        Log.d("NFCPK", Gson().toJson(passkeyCredential))

        setResult(RESULT_OK, result)
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
            processGetCredential(publicKeyCredential)
        }
    }

    private val onMakeCredentialCallback = object : WebauthnDialogFragment.OnMakeCredentialCallback {
        override fun onMakeCredentialResponse(publicKeyCredential: PublicKeyCredential) {
            processCreateCredential(publicKeyCredential)
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
        return kotlin.io.encoding.Base64.UrlSafe.encode(data).replace("=", "")
    }

    private fun b64Decode(data: String): ByteArray {
        return try {
            Base64.decode(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        } catch (e: Exception) {
            ByteArray(0)
        }
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