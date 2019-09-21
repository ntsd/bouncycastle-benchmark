package me.ntsd.javacryptographybenchmark.model;

import java.util.List;


public class BenchmarkResult {

    private String name;
    private List<AlgorithmResult> algorithmResults;
    private long average;
    private long score;

    public BenchmarkResult() {
    }

    public BenchmarkResult(String name, List<AlgorithmResult> algorithmResults, long average, long score) {
        this.name = name;
        this.algorithmResults = algorithmResults;
        this.average = average;
        this.score = score;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<AlgorithmResult> getAlgorithmResults() {
        return algorithmResults;
    }

    public void setAlgorithmResults(List<AlgorithmResult> algorithmResults) {
        this.algorithmResults = algorithmResults;
    }

    public long getAverage() {
        return average;
    }

    public void setAverage(long average) {
        this.average = average;
    }

    public long getScore() {
        return score;
    }

    public void setScore(long score) {
        this.score = score;
    }
}
