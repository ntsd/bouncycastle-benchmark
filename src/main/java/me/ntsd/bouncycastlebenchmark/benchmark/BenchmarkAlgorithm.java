package me.ntsd.bouncycastlebenchmark.benchmark;


public interface BenchmarkAlgorithm {

    String getAlgorithmName();

    void run(String input) throws Exception;
}
