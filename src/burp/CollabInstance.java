package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import static burp.Utilities.callbacks;

public class CollabInstance {

    IBurpCollaboratorClientContext collab;
    HashMap<String, String> tokenToMemory;

    HashSet<String> alreadyReported;

    public CollabInstance() {
        collab = callbacks.createBurpCollaboratorClientContext();
        tokenToMemory = new HashMap<>();
        alreadyReported = new HashSet<>();
    }

    public String generate(String remember) {
        String token = collab.generatePayload(false);
        tokenToMemory.put(token, remember);
        return collab.generatePayload(true);
    }

    public boolean observed(String remember) {
        return alreadyReported.contains(remember);
    }

    public List<String> poll() {
        List<IBurpCollaboratorInteraction> interactions = collab.fetchAllCollaboratorInteractions();
        List<String> remembered = new ArrayList<>();
        for (IBurpCollaboratorInteraction interaction: interactions) {
            String token = interaction.getProperty("interaction_id");
            String remember = tokenToMemory.get(token);
            if (alreadyReported.contains(remember)) {
                continue;
            }
            alreadyReported.add(remember);
            remembered.add(remember);
        }
        return remembered;
    }


}
