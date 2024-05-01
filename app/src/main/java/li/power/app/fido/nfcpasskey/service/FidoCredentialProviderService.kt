package li.power.app.fido.nfcpasskey.service


import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.credentials.exceptions.*
import androidx.credentials.provider.*
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
import com.google.gson.Gson
import de.cotech.hw.fido.WebsafeBase64
import li.power.app.fido.nfcpasskey.model.AppDatabase
import li.power.app.fido.nfcpasskey.model.TokenDao

val ACTION_CREATE_PASSKEY: String = "li.power.app.fido.nfcpasskey.ACTION_CREATE_PASSKEY"
val ACTION_GET_PASSKEY: String = "li.power.app.fido.nfcpasskey.ACTION_GET_PASSKEY"
val EXTRA_TOKEN_ID: String = "li.power.app.fido.nfcpasskey.EXTRA_TOKEN_ID"
val TAG: String = "FidoCPS"

class FidoCredentialProviderService : CredentialProviderService() {

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        val response: BeginCreateCredentialResponse? = processCreateCredentialRequest(request)
        if (response != null) {
            callback.onResult(response)
        } else {
            callback.onError(CreateCredentialUnknownException())
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        for (option in request.beginGetCredentialOptions) {
            if (option is BeginGetPasswordOption) {
                callback.onError(GetCredentialUnsupportedException("Password is not supported"))
                return
            }

            val passkeyEntries: MutableList<CredentialEntry> = mutableListOf()

            if (option is BeginGetPublicKeyCredentialOption) {
                var pkcOption = PublicKeyCredentialRequestOptions(option.requestJson)
                val tokens = AppDatabase.getDatabase(applicationContext).tokenDao.tokens

                for (token in tokens) {
                    val data = Bundle()
                    data.putString("credId",WebsafeBase64.encodeToString("0".encodeToByteArray()))
                    passkeyEntries.add(
                        PublicKeyCredentialEntry.Builder(
                            context = applicationContext,
                            username = token.name,
                            pendingIntent = createNewGetPendingIntent(data),
                            beginGetPublicKeyCredentialOption = option
                        ).build()
                    )
                }

                callback.onResult(BeginGetCredentialResponse(passkeyEntries))
                return
            }
            callback.onError(GetCredentialUnsupportedException("Unknown option"))
        }
    }

    private fun processCreateCredentialRequest(request: BeginCreateCredentialRequest): BeginCreateCredentialResponse? {
        when (request) {
            is BeginCreatePublicKeyCredentialRequest -> {
                return handleCreatePasskeyQuery(request)
            }
        }
        return null
    }

    private fun handleCreatePasskeyQuery(
        request: BeginCreatePublicKeyCredentialRequest
    ): BeginCreateCredentialResponse {

        // Adding two create entries - one for storing credentials to the 'Personal'
        // account, and one for storing them to the 'Family' account. These
        // accounts are local to this sample app only.
        val createEntries: MutableList<CreateEntry> = mutableListOf()
        val tokenDao: TokenDao = AppDatabase.getDatabase(this).getTokenDao()
            for (token in tokenDao.getTokensWithCredentials()) {
                createEntries.add(
                    CreateEntry(
                        token.token.id,
                        createNewPendingIntent(token.token.id),
                        token.token.name,
                        null, null,
                        0,
                        token.credentials.size,
                        token.credentials.size,
                        false
                    )
                )
            }
        createEntries.add(CreateEntry(
            "USB",
            createNewPendingIntent("USB"),
            "USB Authenticator",
            null, null,
            0,
            0,
            0,
            false
        ))
        return BeginCreateCredentialResponse(createEntries)
    }

    private fun createNewPendingIntent(accountId: String): PendingIntent {
        val intent = Intent(ACTION_CREATE_PASSKEY).setPackage(packageName)

        intent.putExtra(EXTRA_TOKEN_ID, accountId)

        return PendingIntent.getActivity(
            applicationContext, 10,
            intent, (PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        )
    }

    private fun createNewGetPendingIntent(
        extra: Bundle? = null,
    ): PendingIntent {
        val intent = Intent(ACTION_GET_PASSKEY).setPackage(this.packageName)
        if (extra != null) {
            intent.putExtra("CREDENTIAL_DATA", extra)
        }

        val requestCode = (1..9999).random()

        return PendingIntent.getActivity(
            applicationContext, requestCode, intent,
            (PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        )
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        TODO("Not yet implemented")
    }

}