package me.ntsd.bouncycastlebenchmark.model;

import java.util.List;


public class BenchmarkResult {
    private String name;
    private List<AlgorithmResult> algorithmResults;
    private Long averageResult;

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

    public Long getAverageResult() {
        return averageResult;
    }

    public void setAverageResult(Long averageResult) {
        this.averageResult = averageResult;
    }
}
