package cic.cs.unb.ca.jnetpcap;

public class IdGenerator {

    private long id;

    public IdGenerator() {
        this.id = 0L;
    }

    public synchronized long nextId() {
        this.id++;
        return this.id;
    }

}
