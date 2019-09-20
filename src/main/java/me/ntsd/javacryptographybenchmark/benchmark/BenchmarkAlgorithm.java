package me.ntsd.javacryptographybenchmark.benchmark;


public interface BenchmarkAlgorithm {

    String getAlgorithmName();

    void run(String input) throws Exception;
}
