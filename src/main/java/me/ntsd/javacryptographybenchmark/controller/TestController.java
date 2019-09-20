package me.ntsd.javacryptographybenchmark.controller;

import me.ntsd.javacryptographybenchmark.benchmark.Benchmark;
import me.ntsd.javacryptographybenchmark.benchmark.BouncyCastleAesBenchmark;
import me.ntsd.javacryptographybenchmark.benchmark.BouncyCastleRsaAndAesBenchmark;
import me.ntsd.javacryptographybenchmark.benchmark.BouncyCastleRsaBenchmark;
import me.ntsd.javacryptographybenchmark.benchmark.JavaAesBenchmark;
import me.ntsd.javacryptographybenchmark.benchmark.JavaRsaAndAesBenchmark;
import me.ntsd.javacryptographybenchmark.benchmark.JavaRsaBenchmark;
import me.ntsd.javacryptographybenchmark.model.BenchmarkResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;


@RestController
public class TestController {

    @PostMapping(path = "/test")
    public List<BenchmarkResult> runTest(@RequestBody(required = false) String message,
                                         @RequestParam(value = "testNumbers", defaultValue = "10,50,100,500") String testNumbers) throws Exception {
        if (message == null) {
            message = "Test Message";
        }

        List<Integer> testNumbersList = new ArrayList<>();
        for (String s : testNumbers.split(",")) {
            testNumbersList.add(Integer.parseInt(s));
        }

        List<BenchmarkResult> benchmarkResultList = new ArrayList<>();

        Benchmark benchmark = new Benchmark();

        BouncyCastleRsaAndAesBenchmark bouncyCastleRsaAndAesBenchmark = new BouncyCastleRsaAndAesBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(bouncyCastleRsaAndAesBenchmark, message, testNumbersList));

        JavaRsaAndAesBenchmark javaRsaAndAesBenchmark = new JavaRsaAndAesBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(javaRsaAndAesBenchmark, message, testNumbersList));

        BouncyCastleRsaBenchmark bouncyCastleRsaBenchmark = new BouncyCastleRsaBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(bouncyCastleRsaBenchmark, message, testNumbersList));

        JavaRsaBenchmark javaRsaBenchmark = new JavaRsaBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(javaRsaBenchmark, message, testNumbersList));

        BouncyCastleAesBenchmark bouncyCastleAesBenchmark = new BouncyCastleAesBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(bouncyCastleAesBenchmark, message, testNumbersList));

        JavaAesBenchmark javaAesBenchmark = new JavaAesBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(javaAesBenchmark, message, testNumbersList));

        return benchmarkResultList;
    }
}
