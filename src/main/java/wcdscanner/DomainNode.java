package wcdscanner;

public class DomainNode {
    private final String domain;
    private final boolean isRoot;

    public DomainNode(String domain, boolean isRoot) {
        this.domain = domain;
        this.isRoot = isRoot;
    }

    public String getDomain() {
        return domain;
    }

    public boolean isRoot() {
        return isRoot;
    }

    @Override
    public String toString() {
        return domain;
    }
}
