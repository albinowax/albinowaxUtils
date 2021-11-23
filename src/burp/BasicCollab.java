package burp;
import java.util.List;
import static burp.Utilities.callbacks;

public class BasicCollab {
    static IBurpCollaboratorClientContext collab = callbacks.createBurpCollaboratorClientContext();

    static public String getPayload() {
        return collab.generatePayload(true);
    }

    static public boolean checkPayload(String payload) {
        List<IBurpCollaboratorInteraction> interactions = collab.fetchCollaboratorInteractionsFor(payload);
        return interactions.size() > 0;
    }
}
