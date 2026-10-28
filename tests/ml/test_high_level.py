#!/usr/bin/env python3
"""Unit tests for high-level network detector."""
import pytest
import numpy as np
import pandas as pd
from datetime import UTC, datetime, timedelta

from backend.ml.high_level import (
    HighLevelDetector, Profiler, Flow, FEATURES, FEATURE_VERSION,
    rule_scores
)


class TestFeatureSchema:
    """Test feature schema consistency."""
    
    def test_feature_count(self):
        assert len(FEATURES) == 92
    
    def test_feature_version(self):
        assert FEATURE_VERSION == 1
    
    def test_no_duplicate_features(self):
        assert len(FEATURES) == len(set(FEATURES))
    
    def test_feature_names_valid(self):
        for f in FEATURES:
            assert isinstance(f, str)
            assert len(f) > 0
            # No spaces or special chars
            assert ' ' not in f


class TestProfilerCausality:
    """Test that profiler updates are causal (no look-ahead)."""
    
    def test_features_before_update(self):
        """Features for flow N should not depend on flow N."""
        profiler = Profiler()
        
        # First flow - no prior state (use PUBLIC IP for external)
        f1 = Flow(ts=1000.0, src='10.0.0.1', dst='8.8.8.8', port=443,
                  process='test.exe')
        feat1 = profiler.features(f1)
        
        # Update with first flow
        profiler.update(f1)
        
        # Second flow - should see first flow in state
        f2 = Flow(ts=1001.0, src='10.0.0.1', dst='8.8.8.8', port=443,
                  process='test.exe')
        feat2 = profiler.features(f2)
        
        pair_novel_idx = FEATURES.index('pair_novel')
        pair_count_log_idx = FEATURES.index('pair_count_log')
        
        # pair_novel should be 1 for first, 0 for second (before update)
        assert feat1[pair_novel_idx] == 1.0  # pair_novel = 1 for first
        assert feat2[pair_novel_idx] == 0.0  # pair_novel = 0 for second
        
        # pair_count_log should be log1p(0)=0 for first, log1p(1) for second
        assert feat1[pair_count_log_idx] == 0.0
        assert abs(feat2[pair_count_log_idx] - np.log1p(1)) < 1e-6
    
    def test_state_independence(self):
        """Two profilers with same history should produce same features."""
        profiler1 = Profiler()
        profiler2 = Profiler()
        
        flows = [
            Flow(ts=1000.0, src='10.0.0.1', dst='192.168.1.1', port=443, process='a.exe'),
            Flow(ts=1001.0, src='10.0.0.1', dst='192.168.1.1', port=443, process='a.exe'),
            Flow(ts=1002.0, src='10.0.0.2', dst='192.168.1.2', port=80, process='b.exe'),
        ]
        
        for f in flows:
            feat1 = profiler1.features(f)
            feat2 = profiler2.features(f)
            np.testing.assert_array_equal(feat1, feat2)
            profiler1.update(f)
            profiler2.update(f)
    
    def test_external_vs_internal_features(self):
        """External interaction features should be 0 for internal IPs."""
        profiler = Profiler()
        
        # Internal destination (RFC1918)
        f_int = Flow(ts=1000.0, src='10.0.0.1', dst='10.0.0.50', port=443, process='test.exe')
        feat_int = profiler.features(f_int)
        
        # External destination (PUBLIC IP)
        profiler2 = Profiler()  # Fresh profiler
        f_ext = Flow(ts=1000.0, src='10.0.0.1', dst='8.8.8.8', port=443, process='test.exe')
        feat_ext = profiler2.features(f_ext)
        
        ext_dst_novel_idx = FEATURES.index('ext_dst_novel')
        
        # ext_dst_novel should be 0 for internal, 1 for external
        assert feat_int[ext_dst_novel_idx] == 0.0
        assert feat_ext[ext_dst_novel_idx] == 1.0


class TestRuleScores:
    """Test rule score computations."""
    
    def test_rule_scores_shape(self):
        """Rule scores should match input shape."""
        X = np.random.rand(100, 92).astype(np.float32)
        pivot, fanout, c2 = rule_scores(X)
        
        assert pivot.shape == (100,)
        assert fanout.shape == (100,)
        assert c2.shape == (100,)
    
    def test_rule_scores_nonnegative(self):
        """Rule scores should be non-negative."""
        X = np.random.rand(100, 92).astype(np.float32)
        pivot, fanout, c2 = rule_scores(X)
        
        assert np.all(pivot >= 0)
        assert np.all(fanout >= 0)
        assert np.all(c2 >= 0)
    
    def test_pivot_requires_novel_dst(self):
        """Pivot score should be 0 when ext_host_proc_dst_novel=0."""
        # Create feature matrix with ext_host_proc_dst_novel = 0
        X = np.zeros((10, 92), dtype=np.float32)
        X[:, 80] = 0.0  # ext_host_proc_dst_novel
        X[:, 64] = 0.1  # ext_proc_ratio
        X[:, 86] = 5.0  # ext_proc_ext_count_log
        
        pivot, _, _ = rule_scores(X)
        assert np.all(pivot == 0.0)
    
    def test_fanout_requires_src_fanout(self):
        """Fanout score should be 0 when ext_src_fanout_log=0."""
        X = np.zeros((10, 92), dtype=np.float32)
        X[:, 66] = 0.0  # ext_src_fanout_log
        X[:, 5] = 0.5   # port_rarity
        X[:, 23] = 1.0  # process_user_writable
        X[:, 21] = 0.5  # process_rarity
        
        _, fanout, _ = rule_scores(X)
        assert np.all(fanout == 0.0)


class TestNormalization:
    """Test rule score normalization (with log1p)."""
    
    def test_normalize_rule_basic(self):
        """Normalization with log1p: log1p(q01)->0, log1p(q99)->1 approximately."""
        det = HighLevelDetector()
        z = np.array([0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 10.0])
        # Params are in LOG1P space (as stored by fit)
        params = {'q01': np.log1p(0.5), 'q99': np.log1p(4.5)}
        
        normed = det._normalize_rule(z, params)
        
        # log1p(0)=0 < log1p(0.5)=0.405 -> should be 0
        assert normed[0] == 0.0
        # log1p(10)=2.398, log1p(4.5)=1.705
        # (2.398 - 0.405) / (1.705 - 0.405) = 1.993/1.3 = 1.53 > 1
        assert normed[-1] > 1.0
    
    def test_normalize_rule_no_clip_upper(self):
        """Normalization should not clip at 1.0."""
        det = HighLevelDetector()
        z = np.array([0.0, 100.0])
        params = {'q01': 0.0, 'q99': np.log1p(1.0)}  # log1p(1) = 0.693
        
        normed = det._normalize_rule(z, params)
        # log1p(100)=4.615, log1p(0)=0, log1p(1)=0.693
        # (4.615 - 0) / (0.693 - 0) = 6.66 > 1
        assert normed[1] > 1.0


class TestHighLevelDetector:
    """Test high-level detector functionality."""
    
    @pytest.fixture
    def sample_data(self):
        """Generate sample training and test data."""
        rng = np.random.default_rng(42)
        X_train = rng.normal(0, 1, (1000, 92)).astype(np.float32)
        X_test = rng.normal(0, 1, (100, 92)).astype(np.float32)
        X_local = rng.normal(0.5, 1, (200, 92)).astype(np.float32)
        return X_train, X_test, X_local
    
    def test_fit_and_predict(self, sample_data):
        """Test basic fit and predict."""
        X_train, X_test, X_local = sample_data
        
        det = HighLevelDetector()
        det.fit(X_train, X_local)
        
        assert det.threshold > 0
        assert det.threshold < 1
        
        scores = det.fused_score(X_test)
        preds = det.predict(X_test)
        
        assert scores.shape == (100,)
        assert preds.shape == (100,)
        assert np.all((preds == 0) | (preds == 1))
    
    def test_score_with_evidence(self, sample_data):
        """Test score_with_evidence returns expected structure."""
        X_train, X_test, X_local = sample_data
        
        det = HighLevelDetector()
        det.fit(X_train, X_local)
        
        evidence = det.score_with_evidence(X_test[:5])
        
        assert len(evidence) == 5
        for e in evidence:
            assert 'fused_score' in e
            assert 'if_score' in e
            assert 'pivot_score' in e
            assert 'fanout_score' in e
            assert 'c2_score' in e
            assert 'is_anomaly' in e
            assert 'threshold' in e
            assert 'evidence' in e
            assert isinstance(e['evidence'], dict)
    
    def test_save_load(self, sample_data, tmp_path):
        """Test save and load preserves model."""
        X_train, X_test, X_local = sample_data
        
        det = HighLevelDetector()
        det.fit(X_train, X_local)
        
        path = tmp_path / 'detector.joblib'
        det.save(path)
        
        det2 = HighLevelDetector.load(path)
        
        assert det2.threshold == det.threshold
        assert det2.feature_version == det.feature_version
        assert det2._rule_norm == det._rule_norm
        
        # Predictions should match
        scores1 = det.fused_score(X_test)
        scores2 = det2.fused_score(X_test)
        np.testing.assert_array_almost_equal(scores1, scores2)
    
    def test_feature_version_mismatch_warning(self, sample_data, tmp_path, caplog):
        """Test warning on feature version mismatch."""
        X_train, _, X_local = sample_data
        
        det = HighLevelDetector()
        det.fit(X_train, X_local)
        
        path = tmp_path / 'detector.joblib'
        det.save(path)
        
        # Manually corrupt feature_version in saved file
        import joblib
        bundle = joblib.load(path)
        bundle['feature_version'] = 999
        joblib.dump(bundle, path)
        
        with caplog.at_level('WARNING'):
            HighLevelDetector.load(path)
            assert 'Feature version mismatch' in caplog.text
    
    def test_threshold_on_local_benign(self, sample_data):
        """Threshold should be set at specified quantile of local benign."""
        X_train, _, X_local = sample_data
        
        for q in [0.99, 0.995, 0.999]:
            det = HighLevelDetector(threshold_quantile=q)
            det.fit(X_train, X_local)
            
            local_scores = det.fused_score(X_local)
            expected_thr = np.quantile(local_scores, q)
            
            assert abs(det.threshold - expected_thr) < 1e-4


class TestIntegration:
    """Integration tests (require database)."""
    
    @pytest.mark.skip(reason="Requires database")
    def test_shadow_scoring_no_mutation(self):
        """Test that shadow scoring doesn't mutate events."""
        pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])