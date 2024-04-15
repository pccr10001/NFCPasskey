package li.power.app.fido.nfcpasskey.model;

import androidx.room.*;

import java.util.List;

@Dao
public interface CredentialDao {

    @Query("SELECT * FROM credentials WHERE credentialId IN (:id) LIMIT 1")
    Credential getCredentialById(String id);

    @Query("SELECT * FROM credentials WHERE userHandle IN (:uh) LIMIT 1")
    Credential getCredentialByUserHandle(String uh);
    @Query("SELECT * FROM credentials WHERE tokenId IN (:id)")
    List<Credential> getCredentialsByTokenId(String id);
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertAll(Credential... credentials);
    @Update(onConflict = OnConflictStrategy.REPLACE)
    void updateAll(Credential... credentials);
    @Delete
    void delete(Credential credential);

}
