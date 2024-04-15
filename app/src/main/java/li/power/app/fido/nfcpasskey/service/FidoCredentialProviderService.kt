package li.power.app.fido.nfcpasskey.service


import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.*
import androidx.credentials.provider.*

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
            if (option is BeginGetPublicKeyCredentialOption) {
                callback.onResult(BeginGetCredentialResponse(ArrayList(), ArrayList(), ArrayList(), null))
                return
            }
            callback.onError(GetCredentialUnsupportedException("Unknown option"))
        }
    }

    fun processCreateCredentialRequest(request: BeginCreateCredentialRequest): BeginCreateCredentialResponse? {
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
        createEntries.add(
            CreateEntry(
                "Test",
                createNewPendingIntent("Test", ACTION_CREATE_PASSKEY)
            )
        )

        createEntries.add(
            CreateEntry(
                "Test",
                createNewPendingIntent("Test", ACTION_CREATE_PASSKEY)
            )
        )

        return BeginCreateCredentialResponse(createEntries)
    }

    private fun createNewPendingIntent(accountId: String, action: String): PendingIntent {
        val intent = Intent(action).setPackage(packageName)

        intent.putExtra(EXTRA_TOKEN_ID, accountId)

        return PendingIntent.getActivity(
            applicationContext, 10,
            intent, (PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
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