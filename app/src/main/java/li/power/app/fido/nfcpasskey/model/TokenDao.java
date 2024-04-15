package li.power.app.fido.nfcpasskey.model;

import androidx.room.*;

import java.util.List;

@Dao
public interface TokenDao {

    @Query("SELECT * FROM tokens")
    List<Token> getTokens();

    @Query("SELECT * FROM tokens WHERE id IN (:id) LIMIT 1")
    Token getTokenById(String id);

    @Transaction
    @Query("SELECT * FROM tokens")
    List<TokenWithCredentials> getTokensWithCredentials();

    @Transaction
    @Query("SELECT * FROM tokens WHERE id IN (:id) LIMIT 1")
    TokenWithCredentials getTokenWithCredentialsById(String id);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertAll(Token... tokens);

    @Update(onConflict = OnConflictStrategy.REPLACE)
    void updateAll(Token... tokens);
    @Delete
    void delete(Token token);
}
