"""
Unit tests for ChRingsMap with ring rebuild optimization.

Tests verify:
- Optimized ring writes (only changed positions)
- Incremental ring updates
- Performance comparison between full and optimized writes
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from katran.bpf.maps.ch_rings_map import ChRingsMap
from katran.core.constants import RING_SIZE


class TestChRingsMapOptimizedWrite:
    """Tests for optimized ring write operations."""

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.get")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_optimized_no_changes(
        self, mock_set: Mock, mock_get: Mock, mock_open: Mock
    ) -> None:
        """Optimized write with no changes writes nothing."""
        # Setup: old ring is [1, 2, 3]
        old_ring = [1, 2, 3]
        mock_get.side_effect = lambda key: old_ring[key % 3]

        with ChRingsMap("/tmp", ring_size=3) as rings:
            # Write same ring with optimization enabled
            written = rings.write_ring(vip_num=0, ring=[1, 2, 3], optimize=True)

            # Should have read the ring but not written anything
            assert mock_get.call_count == 3  # Read 3 positions
            mock_set.assert_not_called()  # No writes
            assert written == 0

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.get")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_optimized_partial_changes(
        self, mock_set: Mock, mock_get: Mock, mock_open: Mock
    ) -> None:
        """Optimized write only updates changed positions."""
        # Setup: old ring is [1, 2, 3, 4, 5]
        old_ring = [1, 2, 3, 4, 5]
        mock_get.side_effect = lambda key: old_ring[key]

        with ChRingsMap("/tmp", ring_size=5) as rings:
            # Write ring with 2 positions changed
            new_ring = [1, 9, 3, 9, 5]  # Positions 1 and 3 changed
            written = rings.write_ring(vip_num=0, ring=new_ring, optimize=True)

            # Should have written only 2 positions
            assert mock_set.call_count == 2
            assert written == 2

            # Verify correct positions were written
            set_calls = {call[0][0]: call[0][1] for call in mock_set.call_args_list}
            assert set_calls == {1: 9, 3: 9}

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.get")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_optimized_all_changes(
        self, mock_set: Mock, mock_get: Mock, mock_open: Mock
    ) -> None:
        """Optimized write with all positions changed writes everything."""
        # Setup: old ring is [1, 1, 1]
        mock_get.return_value = 1

        with ChRingsMap("/tmp", ring_size=3) as rings:
            # Write completely different ring
            written = rings.write_ring(vip_num=0, ring=[2, 2, 2], optimize=True)

            # Should have written all 3 positions
            assert mock_set.call_count == 3
            assert written == 3

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.get")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_unoptimized(
        self, mock_set: Mock, mock_get: Mock, mock_open: Mock
    ) -> None:
        """Unoptimized write always writes all positions."""
        # Setup: old ring is [1, 2, 3]
        mock_get.return_value = 1

        with ChRingsMap("/tmp", ring_size=3) as rings:
            # Write with optimization disabled
            written = rings.write_ring(vip_num=0, ring=[1, 2, 3], optimize=False)

            # Should have written all positions without reading
            mock_get.assert_not_called()  # No reads
            assert mock_set.call_count == 3  # All writes
            assert written == 3

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.get")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_optimized_different_vips(
        self, mock_set: Mock, mock_get: Mock, mock_open: Mock
    ) -> None:
        """Optimized write handles multiple VIPs correctly."""
        ring_size = 5

        def get_value(key: int) -> int:
            # VIP 0: [1, 1, 1, 1, 1]
            # VIP 1: [2, 2, 2, 2, 2]
            if key < ring_size:
                return 1
            else:
                return 2

        mock_get.side_effect = get_value

        with ChRingsMap("/tmp", ring_size=ring_size) as rings:
            # Update VIP 1 (base offset = 5)
            written = rings.write_ring(
                vip_num=1, ring=[2, 9, 2, 2, 2], optimize=True
            )

            # Should have written only position 1 of VIP 1 (absolute index 6)
            assert written == 1
            mock_set.assert_called_once()
            # Position 1 of VIP 1 = base (5) + offset (1) = 6
            assert mock_set.call_args[0][0] == 6
            assert mock_set.call_args[0][1] == 9


class TestChRingsMapIncrementalWrite:
    """Tests for incremental ring write operations."""

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_incremental_no_changes(
        self, mock_set: Mock, mock_open: Mock
    ) -> None:
        """Incremental write with no changes writes nothing."""
        old_ring = [1, 2, 3, 4, 5]
        new_ring = [1, 2, 3, 4, 5]

        with ChRingsMap("/tmp", ring_size=5) as rings:
            changed, written = rings.write_ring_incremental(
                vip_num=0, old_ring=old_ring, new_ring=new_ring
            )

            assert changed == 0
            assert written == 0
            mock_set.assert_not_called()

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_incremental_partial_changes(
        self, mock_set: Mock, mock_open: Mock
    ) -> None:
        """Incremental write only updates changed positions."""
        old_ring = [1, 2, 3, 4, 5]
        new_ring = [1, 9, 3, 9, 5]  # Positions 1 and 3 changed

        with ChRingsMap("/tmp", ring_size=5) as rings:
            changed, written = rings.write_ring_incremental(
                vip_num=0, old_ring=old_ring, new_ring=new_ring
            )

            assert changed == 2
            assert written == 2
            assert mock_set.call_count == 2

            # Verify correct values written
            set_calls = {call[0][0]: call[0][1] for call in mock_set.call_args_list}
            assert set_calls == {1: 9, 3: 9}

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_incremental_all_changes(
        self, mock_set: Mock, mock_open: Mock
    ) -> None:
        """Incremental write with all positions changed."""
        old_ring = [1, 1, 1]
        new_ring = [2, 2, 2]

        with ChRingsMap("/tmp", ring_size=3) as rings:
            changed, written = rings.write_ring_incremental(
                vip_num=0, old_ring=old_ring, new_ring=new_ring
            )

            assert changed == 3
            assert written == 3
            assert mock_set.call_count == 3

    @patch("katran.bpf.map_manager.BpfMap.open")
    def test_write_ring_incremental_size_mismatch(self, mock_open: Mock) -> None:
        """Incremental write validates ring sizes."""
        with ChRingsMap("/tmp", ring_size=5) as rings:
            # Old ring wrong size
            with pytest.raises(ValueError, match="Old ring length"):
                rings.write_ring_incremental(
                    vip_num=0, old_ring=[1, 2, 3], new_ring=[1, 2, 3, 4, 5]
                )

            # New ring wrong size
            with pytest.raises(ValueError, match="New ring length"):
                rings.write_ring_incremental(
                    vip_num=0, old_ring=[1, 2, 3, 4, 5], new_ring=[1, 2, 3]
                )

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_incremental_with_vip_offset(
        self, mock_set: Mock, mock_open: Mock
    ) -> None:
        """Incremental write calculates correct offsets for VIP."""
        ring_size = 5
        old_ring = [1, 1, 1, 1, 1]
        new_ring = [9, 1, 1, 1, 1]  # Position 0 changed

        with ChRingsMap("/tmp", ring_size=ring_size) as rings:
            # Write to VIP 2 (base offset = 2 * 5 = 10)
            changed, written = rings.write_ring_incremental(
                vip_num=2, old_ring=old_ring, new_ring=new_ring
            )

            assert changed == 1
            assert written == 1

            # Should write to absolute position 10 (VIP 2, position 0)
            mock_set.assert_called_once_with(10, 9)


class TestChRingsMapPerformance:
    """Performance comparison tests for optimization."""

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.get")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_optimization_reduces_writes(
        self, mock_set: Mock, mock_get: Mock, mock_open: Mock
    ) -> None:
        """Optimized write significantly reduces BPF syscalls."""
        # Simulate a large ring with only 1% changes
        ring_size = 1000
        old_ring = [1] * ring_size
        new_ring = old_ring.copy()

        # Change only 10 positions (1%)
        for i in range(0, 100, 10):
            new_ring[i] = 2

        mock_get.side_effect = lambda key: old_ring[key]

        with ChRingsMap("/tmp", ring_size=ring_size) as rings:
            # Optimized write
            written_opt = rings.write_ring(vip_num=0, ring=new_ring, optimize=True)
            opt_writes = mock_set.call_count

            mock_set.reset_mock()

            # Unoptimized write
            written_unopt = rings.write_ring(vip_num=0, ring=new_ring, optimize=False)
            unopt_writes = mock_set.call_count

            # Optimized should write only 10 positions
            assert written_opt == 10
            assert opt_writes == 10

            # Unoptimized should write all 1000 positions
            assert written_unopt == 1000
            assert unopt_writes == 1000

            # Optimization reduced writes by 99%
            reduction = (1 - opt_writes / unopt_writes) * 100
            assert reduction >= 99


class TestChRingsMapEdgeCases:
    """Edge case tests for ring optimization."""

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.get")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_optimized_with_zeros(
        self, mock_set: Mock, mock_get: Mock, mock_open: Mock
    ) -> None:
        """Optimized write handles zero values correctly."""
        old_ring = [1, 0, 3]
        mock_get.side_effect = lambda key: old_ring[key]

        with ChRingsMap("/tmp", ring_size=3) as rings:
            # Change position with 0 to non-zero
            new_ring = [1, 5, 3]
            written = rings.write_ring(vip_num=0, ring=new_ring, optimize=True)

            assert written == 1
            mock_set.assert_called_once_with(1, 5)

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.get")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_optimized_to_zeros(
        self, mock_set: Mock, mock_get: Mock, mock_open: Mock
    ) -> None:
        """Optimized write handles changes to zero."""
        old_ring = [1, 2, 3]
        mock_get.side_effect = lambda key: old_ring[key]

        with ChRingsMap("/tmp", ring_size=3) as rings:
            # Change position to 0
            new_ring = [1, 0, 3]
            written = rings.write_ring(vip_num=0, ring=new_ring, optimize=True)

            assert written == 1
            mock_set.assert_called_once_with(1, 0)

    @patch("katran.bpf.map_manager.BpfMap.open")
    @patch("katran.bpf.map_manager.BpfMap.set")
    def test_write_ring_incremental_empty_ring(
        self, mock_set: Mock, mock_open: Mock
    ) -> None:
        """Incremental write handles empty rings."""
        old_ring = [0, 0, 0]
        new_ring = [1, 2, 3]

        with ChRingsMap("/tmp", ring_size=3) as rings:
            changed, written = rings.write_ring_incremental(
                vip_num=0, old_ring=old_ring, new_ring=new_ring
            )

            # All positions changed from 0 to non-zero
            assert changed == 3
            assert written == 3
