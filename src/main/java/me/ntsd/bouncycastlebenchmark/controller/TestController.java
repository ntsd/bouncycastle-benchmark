package me.ntsd.bouncycastlebenchmark.controller;

import me.ntsd.bouncycastlebenchmark.benchmark.Benchmark;
import me.ntsd.bouncycastlebenchmark.encryption.BouncyCastleRsaAndAesBenchmark;
import me.ntsd.bouncycastlebenchmark.encryption.BouncyCastleRsaBenchmark;
import me.ntsd.bouncycastlebenchmark.encryption.JavaRsaAndAesBenchmark;
import me.ntsd.bouncycastlebenchmark.encryption.JavaRsaBenchmark;
import me.ntsd.bouncycastlebenchmark.model.BenchmarkResult;
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
        BouncyCastleRsaBenchmark bouncyCastleRsaBenchmark = new BouncyCastleRsaBenchmark();

        JavaRsaAndAesBenchmark javaRsaAndAesBenchmark = new JavaRsaAndAesBenchmark();
        JavaRsaBenchmark javaRsaBenchmark = new JavaRsaBenchmark();

        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(bouncyCastleRsaAndAesBenchmark, message, Arrays.asList(10, 50, 100)));
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(javaRsaAndAesBenchmark, message, Arrays.asList(10, 50, 100)));

        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(bouncyCastleRsaBenchmark, message, Arrays.asList(10, 50, 100, 500)));
        benchmarkResultList.add(benchmark.getAlgorithmBenchmarkResult(javaRsaBenchmark, message, Arrays.asList(10, 50, 100, 500)));

        return benchmarkResultList;
    }
}
