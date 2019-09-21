package me.ntsd.javacryptographybenchmark.model;


public class AlgorithmResult {

    private long score;
    private long average;
    private int number;

    public AlgorithmResult() {
    }

    public AlgorithmResult(long score, long average, int number) {
        this.score = score;
        this.average = average;
        this.number = number;
    }

    public long getScore() {
        return score;
    }

    public void setScore(long score) {
        this.score = score;
    }

    public long getAverage() {
        return average;
    }

    public void setAverage(long average) {
        this.average = average;
    }

    public int getNumber() {
        return number;
    }

    public void setNumber(int number) {
        this.number = number;
    }
}
