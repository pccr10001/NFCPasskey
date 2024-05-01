package li.power.app.fido.nfcpasskey.model;


import android.util.Base64;
import androidx.annotation.NonNull;
import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

import java.io.Serializable;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Date;

@Entity(tableName = "credentials")
public class Credential implements Serializable {
    @PrimaryKey
    @ColumnInfo(name = "credentialId")
    @NonNull
    private String credentialId;
    @ColumnInfo(name = "rpId")
    @NonNull
    private String rpId;
    @ColumnInfo(name = "serviceName")
    private String serviceName;
    @ColumnInfo(name = "userHandle")
    private String userHandle;
    @ColumnInfo(name = "displayName")
    private String displayName;
    @ColumnInfo(name = "publicKey")
    @NonNull
    private String publicKey;
    @ColumnInfo(name = "tokenId")
    private String tokenId;

    @ColumnInfo(name = "created")
    private long created;

    @ColumnInfo(name = "lastUsed")
    private long lastUsed;

    public Credential(@NonNull String credentialId, @NonNull String rpId, String serviceName, String userHandle, String displayName, @NonNull String publicKey, String tokenId) {
        this.credentialId = credentialId;
        this.rpId = rpId;
        this.serviceName = serviceName;
        this.userHandle = userHandle;
        this.displayName = displayName;
        this.publicKey = publicKey;
        this.tokenId = tokenId;
        this.created = new java.util.Date().getTime();
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public byte[] getCredentialIdBytes() {
        return Base64.decode(credentialId, Base64.URL_SAFE | Base64.NO_PADDING);
    }

    public void setCredentialIdBytes(byte[] credentialId) {
        this.credentialId = Base64.encodeToString(credentialId, Base64.URL_SAFE | Base64.NO_PADDING);
    }

    public byte[] getUserHandleBytes() {
        return Base64.decode(userHandle, Base64.URL_SAFE | Base64.NO_PADDING);
    }

    public void setUserHandleBytes(byte[] userHandle) {
        this.userHandle = Base64.encodeToString(userHandle, Base64.URL_SAFE | Base64.NO_PADDING);
    }

    public String getUserHandle() {
        return userHandle;
    }

    public void setUserHandle(String userHandle) {
        this.userHandle = userHandle;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    public long getCreated() {
        return created;
    }

    public void setCreated(long created) {
        this.created = created;
    }

    public long getLastUsed() {
        return lastUsed;
    }

    public void setLastUsed(long lastUsed) {
        this.lastUsed = lastUsed;
    }
}
