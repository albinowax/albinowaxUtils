package burp;

import org.apache.commons.lang3.StringUtils;

import java.util.Comparator;

class SortByParentDomain implements Comparator<ScanItem> {
    @Override
    public int compare(ScanItem o1, ScanItem o2) {

        // prioritise domains with fewer dots
        int dot1 = StringUtils.countMatches(o1.host, ".");
        int dot2 = StringUtils.countMatches(o2.host, ".");
        int score = dot1 - dot2;

        // prioritise shorter domains
        if (score == 0) {
            score = o1.host.length() - o2.host.length();
        }

        // prioritise based on domain hashcode
        // this is just to reduce load on the expensive path-based prioritisation
        if (score == 0) {
            score = o1.hashCode() - o2.hashCode();
        }

        // finally, prioritise requests with longer paths
        if (score == 0) {
            String path1 = Utilities.getPathFromRequest(o1.req.getRequest());
            String path2 = Utilities.getPathFromRequest(o2.req.getRequest());
            score = path2.length() - path1.length();
        }

        return score;
    }
}
