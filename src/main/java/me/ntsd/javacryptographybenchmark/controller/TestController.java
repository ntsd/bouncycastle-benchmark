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
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


@RestController
public class TestController {

    @PostMapping(path = "/test")
    public List<BenchmarkResult> runTest(@RequestBody String message) throws Exception {
        List<BenchmarkResult> benchmarkResultList = new ArrayList<>();

        Benchmark benchmark = new Benchmark();

        BouncyCastleRsaAndAesBenchmark bouncyCastleRsaAndAesBenchmark = new BouncyCastleRsaAndAesBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(bouncyCastleRsaAndAesBenchmark, message, Arrays.asList(10, 50, 100, 500)));

        JavaRsaAndAesBenchmark javaRsaAndAesBenchmark = new JavaRsaAndAesBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(javaRsaAndAesBenchmark, message, Arrays.asList(10, 50, 100, 500)));

        BouncyCastleRsaBenchmark bouncyCastleRsaBenchmark = new BouncyCastleRsaBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(bouncyCastleRsaBenchmark, message, Arrays.asList(10, 50, 100, 500)));

        JavaRsaBenchmark javaRsaBenchmark = new JavaRsaBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(javaRsaBenchmark, message, Arrays.asList(10, 50, 100, 500)));

        BouncyCastleAesBenchmark bouncyCastleAesBenchmark = new BouncyCastleAesBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(bouncyCastleAesBenchmark, message, Arrays.asList(10, 50, 100, 500)));

        JavaAesBenchmark javaAesBenchmark = new JavaAesBenchmark();
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(javaAesBenchmark, message, Arrays.asList(10, 50, 100, 500)));

        return benchmarkResultList;
    }
}
