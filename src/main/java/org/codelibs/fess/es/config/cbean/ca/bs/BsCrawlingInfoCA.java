/*
 * Copyright 2012-2016 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.fess.es.config.cbean.ca.bs;

import org.codelibs.fess.es.config.allcommon.EsAbstractConditionAggregation;
import org.codelibs.fess.es.config.allcommon.EsAbstractConditionQuery;
import org.codelibs.fess.es.config.cbean.ca.CrawlingInfoCA;
import org.codelibs.fess.es.config.cbean.cq.CrawlingInfoCQ;
import org.codelibs.fess.es.config.cbean.cq.bs.BsCrawlingInfoCQ;
import org.elasticsearch.search.aggregations.bucket.filter.FilterAggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.global.GlobalBuilder;
import org.elasticsearch.search.aggregations.bucket.histogram.HistogramBuilder;
import org.elasticsearch.search.aggregations.bucket.missing.MissingBuilder;
import org.elasticsearch.search.aggregations.bucket.range.RangeBuilder;
import org.elasticsearch.search.aggregations.bucket.range.ipv4.IPv4RangeBuilder;
import org.elasticsearch.search.aggregations.bucket.sampler.SamplerAggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.significant.SignificantTermsBuilder;
import org.elasticsearch.search.aggregations.bucket.terms.TermsBuilder;
import org.elasticsearch.search.aggregations.metrics.avg.AvgBuilder;
import org.elasticsearch.search.aggregations.metrics.cardinality.CardinalityBuilder;
import org.elasticsearch.search.aggregations.metrics.max.MaxBuilder;
import org.elasticsearch.search.aggregations.metrics.min.MinBuilder;
import org.elasticsearch.search.aggregations.metrics.percentiles.PercentileRanksBuilder;
import org.elasticsearch.search.aggregations.metrics.percentiles.PercentilesBuilder;
import org.elasticsearch.search.aggregations.metrics.scripted.ScriptedMetricBuilder;
import org.elasticsearch.search.aggregations.metrics.stats.StatsBuilder;
import org.elasticsearch.search.aggregations.metrics.stats.extended.ExtendedStatsBuilder;
import org.elasticsearch.search.aggregations.metrics.sum.SumBuilder;
import org.elasticsearch.search.aggregations.metrics.tophits.TopHitsBuilder;
import org.elasticsearch.search.aggregations.metrics.valuecount.ValueCountBuilder;

/**
 * @author ESFlute (using FreeGen)
 */
public abstract class BsCrawlingInfoCA extends EsAbstractConditionAggregation {

    // ===================================================================================
    //                                                                     Aggregation Set
    //                                                                           =========

    public void filter(String name, EsAbstractConditionQuery.OperatorCall<BsCrawlingInfoCQ> queryLambda,
            ConditionOptionCall<FilterAggregationBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        CrawlingInfoCQ cq = new CrawlingInfoCQ();
        if (queryLambda != null) {
            queryLambda.callback(cq);
        }
        FilterAggregationBuilder builder = regFilterA(name, cq.getQuery());
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void global(String name, ConditionOptionCall<GlobalBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        GlobalBuilder builder = regGlobalA(name);
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void sampler(String name, ConditionOptionCall<SamplerAggregationBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        SamplerAggregationBuilder builder = regSamplerA(name);
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void scriptedMetric(String name, ConditionOptionCall<ScriptedMetricBuilder> opLambda) {
        ScriptedMetricBuilder builder = regScriptedMetricA(name);
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void topHits(String name, ConditionOptionCall<TopHitsBuilder> opLambda) {
        TopHitsBuilder builder = regTopHitsA(name);
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    // Long createdTime
    public void setCreatedTime_Avg() {
        setCreatedTime_Avg(null);
    }

    public void setCreatedTime_Avg(ConditionOptionCall<AvgBuilder> opLambda) {
        setCreatedTime_Avg("createdTime", opLambda);
    }

    public void setCreatedTime_Avg(String name, ConditionOptionCall<AvgBuilder> opLambda) {
        AvgBuilder builder = regAvgA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_Max() {
        setCreatedTime_Max(null);
    }

    public void setCreatedTime_Max(ConditionOptionCall<MaxBuilder> opLambda) {
        setCreatedTime_Max("createdTime", opLambda);
    }

    public void setCreatedTime_Max(String name, ConditionOptionCall<MaxBuilder> opLambda) {
        MaxBuilder builder = regMaxA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_Min() {
        setCreatedTime_Min(null);
    }

    public void setCreatedTime_Min(ConditionOptionCall<MinBuilder> opLambda) {
        setCreatedTime_Min("createdTime", opLambda);
    }

    public void setCreatedTime_Min(String name, ConditionOptionCall<MinBuilder> opLambda) {
        MinBuilder builder = regMinA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_Sum() {
        setCreatedTime_Sum(null);
    }

    public void setCreatedTime_Sum(ConditionOptionCall<SumBuilder> opLambda) {
        setCreatedTime_Sum("createdTime", opLambda);
    }

    public void setCreatedTime_Sum(String name, ConditionOptionCall<SumBuilder> opLambda) {
        SumBuilder builder = regSumA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_ExtendedStats() {
        setCreatedTime_ExtendedStats(null);
    }

    public void setCreatedTime_ExtendedStats(ConditionOptionCall<ExtendedStatsBuilder> opLambda) {
        setCreatedTime_ExtendedStats("createdTime", opLambda);
    }

    public void setCreatedTime_ExtendedStats(String name, ConditionOptionCall<ExtendedStatsBuilder> opLambda) {
        ExtendedStatsBuilder builder = regExtendedStatsA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_Stats() {
        setCreatedTime_Stats(null);
    }

    public void setCreatedTime_Stats(ConditionOptionCall<StatsBuilder> opLambda) {
        setCreatedTime_Stats("createdTime", opLambda);
    }

    public void setCreatedTime_Stats(String name, ConditionOptionCall<StatsBuilder> opLambda) {
        StatsBuilder builder = regStatsA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_Percentiles() {
        setCreatedTime_Percentiles(null);
    }

    public void setCreatedTime_Percentiles(ConditionOptionCall<PercentilesBuilder> opLambda) {
        setCreatedTime_Percentiles("createdTime", opLambda);
    }

    public void setCreatedTime_Percentiles(String name, ConditionOptionCall<PercentilesBuilder> opLambda) {
        PercentilesBuilder builder = regPercentilesA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_PercentileRanks() {
        setCreatedTime_PercentileRanks(null);
    }

    public void setCreatedTime_PercentileRanks(ConditionOptionCall<PercentileRanksBuilder> opLambda) {
        setCreatedTime_PercentileRanks("createdTime", opLambda);
    }

    public void setCreatedTime_PercentileRanks(String name, ConditionOptionCall<PercentileRanksBuilder> opLambda) {
        PercentileRanksBuilder builder = regPercentileRanksA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_Histogram() {
        setCreatedTime_Histogram(null);
    }

    public void setCreatedTime_Histogram(ConditionOptionCall<HistogramBuilder> opLambda) {
        setCreatedTime_Histogram("createdTime", opLambda, null);
    }

    public void setCreatedTime_Histogram(ConditionOptionCall<HistogramBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setCreatedTime_Histogram("createdTime", opLambda, aggsLambda);
    }

    public void setCreatedTime_Histogram(String name, ConditionOptionCall<HistogramBuilder> opLambda,
            OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        HistogramBuilder builder = regHistogramA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setCreatedTime_Range() {
        setCreatedTime_Range(null);
    }

    public void setCreatedTime_Range(ConditionOptionCall<RangeBuilder> opLambda) {
        setCreatedTime_Range("createdTime", opLambda, null);
    }

    public void setCreatedTime_Range(ConditionOptionCall<RangeBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setCreatedTime_Range("createdTime", opLambda, aggsLambda);
    }

    public void setCreatedTime_Range(String name, ConditionOptionCall<RangeBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        RangeBuilder builder = regRangeA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setCreatedTime_Count() {
        setCreatedTime_Count(null);
    }

    public void setCreatedTime_Count(ConditionOptionCall<ValueCountBuilder> opLambda) {
        setCreatedTime_Count("createdTime", opLambda);
    }

    public void setCreatedTime_Count(String name, ConditionOptionCall<ValueCountBuilder> opLambda) {
        ValueCountBuilder builder = regCountA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_Cardinality() {
        setCreatedTime_Cardinality(null);
    }

    public void setCreatedTime_Cardinality(ConditionOptionCall<CardinalityBuilder> opLambda) {
        setCreatedTime_Cardinality("createdTime", opLambda);
    }

    public void setCreatedTime_Cardinality(String name, ConditionOptionCall<CardinalityBuilder> opLambda) {
        CardinalityBuilder builder = regCardinalityA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setCreatedTime_Missing() {
        setCreatedTime_Missing(null);
    }

    public void setCreatedTime_Missing(ConditionOptionCall<MissingBuilder> opLambda) {
        setCreatedTime_Missing("createdTime", opLambda, null);
    }

    public void setCreatedTime_Missing(ConditionOptionCall<MissingBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setCreatedTime_Missing("createdTime", opLambda, aggsLambda);
    }

    public void setCreatedTime_Missing(String name, ConditionOptionCall<MissingBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        MissingBuilder builder = regMissingA(name, "createdTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    // Long expiredTime
    public void setExpiredTime_Avg() {
        setExpiredTime_Avg(null);
    }

    public void setExpiredTime_Avg(ConditionOptionCall<AvgBuilder> opLambda) {
        setExpiredTime_Avg("expiredTime", opLambda);
    }

    public void setExpiredTime_Avg(String name, ConditionOptionCall<AvgBuilder> opLambda) {
        AvgBuilder builder = regAvgA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_Max() {
        setExpiredTime_Max(null);
    }

    public void setExpiredTime_Max(ConditionOptionCall<MaxBuilder> opLambda) {
        setExpiredTime_Max("expiredTime", opLambda);
    }

    public void setExpiredTime_Max(String name, ConditionOptionCall<MaxBuilder> opLambda) {
        MaxBuilder builder = regMaxA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_Min() {
        setExpiredTime_Min(null);
    }

    public void setExpiredTime_Min(ConditionOptionCall<MinBuilder> opLambda) {
        setExpiredTime_Min("expiredTime", opLambda);
    }

    public void setExpiredTime_Min(String name, ConditionOptionCall<MinBuilder> opLambda) {
        MinBuilder builder = regMinA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_Sum() {
        setExpiredTime_Sum(null);
    }

    public void setExpiredTime_Sum(ConditionOptionCall<SumBuilder> opLambda) {
        setExpiredTime_Sum("expiredTime", opLambda);
    }

    public void setExpiredTime_Sum(String name, ConditionOptionCall<SumBuilder> opLambda) {
        SumBuilder builder = regSumA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_ExtendedStats() {
        setExpiredTime_ExtendedStats(null);
    }

    public void setExpiredTime_ExtendedStats(ConditionOptionCall<ExtendedStatsBuilder> opLambda) {
        setExpiredTime_ExtendedStats("expiredTime", opLambda);
    }

    public void setExpiredTime_ExtendedStats(String name, ConditionOptionCall<ExtendedStatsBuilder> opLambda) {
        ExtendedStatsBuilder builder = regExtendedStatsA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_Stats() {
        setExpiredTime_Stats(null);
    }

    public void setExpiredTime_Stats(ConditionOptionCall<StatsBuilder> opLambda) {
        setExpiredTime_Stats("expiredTime", opLambda);
    }

    public void setExpiredTime_Stats(String name, ConditionOptionCall<StatsBuilder> opLambda) {
        StatsBuilder builder = regStatsA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_Percentiles() {
        setExpiredTime_Percentiles(null);
    }

    public void setExpiredTime_Percentiles(ConditionOptionCall<PercentilesBuilder> opLambda) {
        setExpiredTime_Percentiles("expiredTime", opLambda);
    }

    public void setExpiredTime_Percentiles(String name, ConditionOptionCall<PercentilesBuilder> opLambda) {
        PercentilesBuilder builder = regPercentilesA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_PercentileRanks() {
        setExpiredTime_PercentileRanks(null);
    }

    public void setExpiredTime_PercentileRanks(ConditionOptionCall<PercentileRanksBuilder> opLambda) {
        setExpiredTime_PercentileRanks("expiredTime", opLambda);
    }

    public void setExpiredTime_PercentileRanks(String name, ConditionOptionCall<PercentileRanksBuilder> opLambda) {
        PercentileRanksBuilder builder = regPercentileRanksA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_Histogram() {
        setExpiredTime_Histogram(null);
    }

    public void setExpiredTime_Histogram(ConditionOptionCall<HistogramBuilder> opLambda) {
        setExpiredTime_Histogram("expiredTime", opLambda, null);
    }

    public void setExpiredTime_Histogram(ConditionOptionCall<HistogramBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setExpiredTime_Histogram("expiredTime", opLambda, aggsLambda);
    }

    public void setExpiredTime_Histogram(String name, ConditionOptionCall<HistogramBuilder> opLambda,
            OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        HistogramBuilder builder = regHistogramA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setExpiredTime_Range() {
        setExpiredTime_Range(null);
    }

    public void setExpiredTime_Range(ConditionOptionCall<RangeBuilder> opLambda) {
        setExpiredTime_Range("expiredTime", opLambda, null);
    }

    public void setExpiredTime_Range(ConditionOptionCall<RangeBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setExpiredTime_Range("expiredTime", opLambda, aggsLambda);
    }

    public void setExpiredTime_Range(String name, ConditionOptionCall<RangeBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        RangeBuilder builder = regRangeA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setExpiredTime_Count() {
        setExpiredTime_Count(null);
    }

    public void setExpiredTime_Count(ConditionOptionCall<ValueCountBuilder> opLambda) {
        setExpiredTime_Count("expiredTime", opLambda);
    }

    public void setExpiredTime_Count(String name, ConditionOptionCall<ValueCountBuilder> opLambda) {
        ValueCountBuilder builder = regCountA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_Cardinality() {
        setExpiredTime_Cardinality(null);
    }

    public void setExpiredTime_Cardinality(ConditionOptionCall<CardinalityBuilder> opLambda) {
        setExpiredTime_Cardinality("expiredTime", opLambda);
    }

    public void setExpiredTime_Cardinality(String name, ConditionOptionCall<CardinalityBuilder> opLambda) {
        CardinalityBuilder builder = regCardinalityA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setExpiredTime_Missing() {
        setExpiredTime_Missing(null);
    }

    public void setExpiredTime_Missing(ConditionOptionCall<MissingBuilder> opLambda) {
        setExpiredTime_Missing("expiredTime", opLambda, null);
    }

    public void setExpiredTime_Missing(ConditionOptionCall<MissingBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setExpiredTime_Missing("expiredTime", opLambda, aggsLambda);
    }

    public void setExpiredTime_Missing(String name, ConditionOptionCall<MissingBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        MissingBuilder builder = regMissingA(name, "expiredTime");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    // String name

    public void setName_Terms() {
        setName_Terms(null);
    }

    public void setName_Terms(ConditionOptionCall<TermsBuilder> opLambda) {
        setName_Terms("name", opLambda, null);
    }

    public void setName_Terms(ConditionOptionCall<TermsBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setName_Terms("name", opLambda, aggsLambda);
    }

    public void setName_Terms(String name, ConditionOptionCall<TermsBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        TermsBuilder builder = regTermsA(name, "name");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setName_SignificantTerms() {
        setName_SignificantTerms(null);
    }

    public void setName_SignificantTerms(ConditionOptionCall<SignificantTermsBuilder> opLambda) {
        setName_SignificantTerms("name", opLambda, null);
    }

    public void setName_SignificantTerms(ConditionOptionCall<SignificantTermsBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setName_SignificantTerms("name", opLambda, aggsLambda);
    }

    public void setName_SignificantTerms(String name, ConditionOptionCall<SignificantTermsBuilder> opLambda,
            OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        SignificantTermsBuilder builder = regSignificantTermsA(name, "name");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setName_IpRange() {
        setName_IpRange(null);
    }

    public void setName_IpRange(ConditionOptionCall<IPv4RangeBuilder> opLambda) {
        setName_IpRange("name", opLambda, null);
    }

    public void setName_IpRange(ConditionOptionCall<IPv4RangeBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setName_IpRange("name", opLambda, aggsLambda);
    }

    public void setName_IpRange(String name, ConditionOptionCall<IPv4RangeBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        IPv4RangeBuilder builder = regIpRangeA(name, "name");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setName_Count() {
        setName_Count(null);
    }

    public void setName_Count(ConditionOptionCall<ValueCountBuilder> opLambda) {
        setName_Count("name", opLambda);
    }

    public void setName_Count(String name, ConditionOptionCall<ValueCountBuilder> opLambda) {
        ValueCountBuilder builder = regCountA(name, "name");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setName_Cardinality() {
        setName_Cardinality(null);
    }

    public void setName_Cardinality(ConditionOptionCall<CardinalityBuilder> opLambda) {
        setName_Cardinality("name", opLambda);
    }

    public void setName_Cardinality(String name, ConditionOptionCall<CardinalityBuilder> opLambda) {
        CardinalityBuilder builder = regCardinalityA(name, "name");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setName_Missing() {
        setName_Missing(null);
    }

    public void setName_Missing(ConditionOptionCall<MissingBuilder> opLambda) {
        setName_Missing("name", opLambda, null);
    }

    public void setName_Missing(ConditionOptionCall<MissingBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setName_Missing("name", opLambda, aggsLambda);
    }

    public void setName_Missing(String name, ConditionOptionCall<MissingBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        MissingBuilder builder = regMissingA(name, "name");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    // String sessionId

    public void setSessionId_Terms() {
        setSessionId_Terms(null);
    }

    public void setSessionId_Terms(ConditionOptionCall<TermsBuilder> opLambda) {
        setSessionId_Terms("sessionId", opLambda, null);
    }

    public void setSessionId_Terms(ConditionOptionCall<TermsBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setSessionId_Terms("sessionId", opLambda, aggsLambda);
    }

    public void setSessionId_Terms(String name, ConditionOptionCall<TermsBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        TermsBuilder builder = regTermsA(name, "sessionId");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setSessionId_SignificantTerms() {
        setSessionId_SignificantTerms(null);
    }

    public void setSessionId_SignificantTerms(ConditionOptionCall<SignificantTermsBuilder> opLambda) {
        setSessionId_SignificantTerms("sessionId", opLambda, null);
    }

    public void setSessionId_SignificantTerms(ConditionOptionCall<SignificantTermsBuilder> opLambda,
            OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setSessionId_SignificantTerms("sessionId", opLambda, aggsLambda);
    }

    public void setSessionId_SignificantTerms(String name, ConditionOptionCall<SignificantTermsBuilder> opLambda,
            OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        SignificantTermsBuilder builder = regSignificantTermsA(name, "sessionId");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setSessionId_IpRange() {
        setSessionId_IpRange(null);
    }

    public void setSessionId_IpRange(ConditionOptionCall<IPv4RangeBuilder> opLambda) {
        setSessionId_IpRange("sessionId", opLambda, null);
    }

    public void setSessionId_IpRange(ConditionOptionCall<IPv4RangeBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setSessionId_IpRange("sessionId", opLambda, aggsLambda);
    }

    public void setSessionId_IpRange(String name, ConditionOptionCall<IPv4RangeBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        IPv4RangeBuilder builder = regIpRangeA(name, "sessionId");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

    public void setSessionId_Count() {
        setSessionId_Count(null);
    }

    public void setSessionId_Count(ConditionOptionCall<ValueCountBuilder> opLambda) {
        setSessionId_Count("sessionId", opLambda);
    }

    public void setSessionId_Count(String name, ConditionOptionCall<ValueCountBuilder> opLambda) {
        ValueCountBuilder builder = regCountA(name, "sessionId");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setSessionId_Cardinality() {
        setSessionId_Cardinality(null);
    }

    public void setSessionId_Cardinality(ConditionOptionCall<CardinalityBuilder> opLambda) {
        setSessionId_Cardinality("sessionId", opLambda);
    }

    public void setSessionId_Cardinality(String name, ConditionOptionCall<CardinalityBuilder> opLambda) {
        CardinalityBuilder builder = regCardinalityA(name, "sessionId");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
    }

    public void setSessionId_Missing() {
        setSessionId_Missing(null);
    }

    public void setSessionId_Missing(ConditionOptionCall<MissingBuilder> opLambda) {
        setSessionId_Missing("sessionId", opLambda, null);
    }

    public void setSessionId_Missing(ConditionOptionCall<MissingBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        setSessionId_Missing("sessionId", opLambda, aggsLambda);
    }

    public void setSessionId_Missing(String name, ConditionOptionCall<MissingBuilder> opLambda, OperatorCall<BsCrawlingInfoCA> aggsLambda) {
        MissingBuilder builder = regMissingA(name, "sessionId");
        if (opLambda != null) {
            opLambda.callback(builder);
        }
        if (aggsLambda != null) {
            CrawlingInfoCA ca = new CrawlingInfoCA();
            aggsLambda.callback(ca);
            ca.getAggregationBuilderList().forEach(builder::subAggregation);
        }
    }

}
