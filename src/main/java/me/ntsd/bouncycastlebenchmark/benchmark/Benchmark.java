package me.ntsd.bouncycastlebenchmark.benchmark;

import me.ntsd.bouncycastlebenchmark.model.AlgorithmResult;
import me.ntsd.bouncycastlebenchmark.model.BenchmarkResult;

import java.util.ArrayList;
import java.util.List;


public class Benchmark {

    public BenchmarkResult getAlgorithmBenchmarkResult(BenchmarkAlgorithm benchmarkAlgorithm, String input, List<Integer> numbers) throws Exception {
        BenchmarkResult benchmarkResult = new BenchmarkResult();
        benchmarkResult.setName(benchmarkAlgorithm.getAlgorithmName());

        List<AlgorithmResult> algorithmResultList = new ArrayList<>();

        Long timeAll = 0L;
        Integer numbersAll = 0;

        for (int i = 0; i < numbers.size(); i++) {
            Long startTime = System.nanoTime();

            AlgorithmResult algorithmResult = new AlgorithmResult();

            algorithmResult.setNumber(numbers.get(i));
            numbersAll += numbers.get(i);

            for (int j = 0; j < numbers.get(i); j++) {
                benchmarkAlgorithm.run(input);
            }

            Long time = System.nanoTime() - startTime;

            timeAll += time;
            algorithmResult.setTime(time);

            algorithmResultList.add(algorithmResult);
        }

        benchmarkResult.setAverageResult(timeAll / numbersAll);

        benchmarkResult.setAlgorithmResults(algorithmResultList);

        return benchmarkResult;
    }
}
