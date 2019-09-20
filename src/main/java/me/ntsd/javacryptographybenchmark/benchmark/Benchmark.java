package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.model.AlgorithmResult;
import me.ntsd.javacryptographybenchmark.model.BenchmarkResult;

import java.util.ArrayList;
import java.util.List;


public class Benchmark {

    public BenchmarkResult getAlgorithmBenchmarkResult(BenchmarkAlgorithm benchmarkAlgorithm, String input, List<Integer> numbers) throws Exception {
        BenchmarkResult benchmarkResult = new BenchmarkResult();
        benchmarkResult.setName(benchmarkAlgorithm.getAlgorithmName());

        List<AlgorithmResult> algorithmResultList = new ArrayList<>();

        long timeAll = 0L;
        int numbersAll = 0;

        for (int number : numbers) {
            AlgorithmResult algorithmResult = new AlgorithmResult();

            algorithmResult.setNumber(number);
            numbersAll += number;

            long startTime = System.nanoTime();

            for (int j = 0; j < number; j++) {
                benchmarkAlgorithm.run(input);
            }

            long time = System.nanoTime() - startTime;

            timeAll += time;
            algorithmResult.setTime(time);

            algorithmResultList.add(algorithmResult);
        }

        benchmarkResult.setSumResult(timeAll);

        benchmarkResult.setAverageResult(timeAll / numbersAll);

        benchmarkResult.setAlgorithmResults(algorithmResultList);

        return benchmarkResult;
    }
}
