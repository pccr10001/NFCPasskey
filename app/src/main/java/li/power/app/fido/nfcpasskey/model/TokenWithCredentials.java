package li.power.app.fido.nfcpasskey.model;

import androidx.room.Embedded;
import androidx.room.Relation;

import java.util.List;

public class TokenWithCredentials {
    @Embedded
    public Token token;
    @Relation(
            parentColumn = "id",
            entityColumn = "tokenId"
    )
    public List<Credential> credentials;

}
