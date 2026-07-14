package guest

import (
	"errors"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/readiness"
	wago "github.com/wago-org/wago"
)

var errPollEncoding = errors.New("net: failed to encode validated guest poll output")

// Poll performs the shared checked, quota-accounted, bounded readiness pass for
// an independently registered protocol import.
func Poll(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		SetStatus(results, StatusInvalidArgument)
		return
	}
	memory := Memory(module)
	eventsPtr, eventsOK := abicore.NarrowUint32(params[0])
	eventCapacity, capacityOK := abicore.NarrowUint32(params[1])
	budgetPtr, budgetOK := abicore.NarrowUint32(params[2])
	resultPtr, resultOK := abicore.NarrowUint32(params[3])
	if !eventsOK || !capacityOK || !budgetOK || !resultOK {
		SetStatus(results, StatusInvalidArgument)
		return
	}
	budget, ok := abicore.DecodePollBudgetV1(memory, budgetPtr)
	if !ok || budget.Events > eventCapacity {
		SetStatus(results, StatusInvalidArgument)
		return
	}
	eventBytes := uint64(eventCapacity) * uint64(abicore.PollEventV1Size)
	if eventBytes > uint64(^uint32(0)) {
		SetStatus(results, StatusInvalidArgument)
		return
	}
	if !abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: eventsPtr, Length: uint32(eventBytes)},
		abicore.Range{Ptr: resultPtr, Length: abicore.PollResultV1Size},
	) {
		SetStatus(results, StatusInvalidArgument)
		return
	}
	state, ok := host.State(module)
	if !ok || state == nil {
		SetStatus(results, StatusInvalidState)
		return
	}
	var progress nscore.Progress
	var pollErr error
	err := state.Quotas().WithService(pollWorkUnits(budget), func() {
		_, progress, pollErr = state.Poll(budget, func(events []readiness.Event, report readiness.Report, _ nscore.Progress) error {
			if !abicore.EncodePollEventsV1(memory, eventsPtr, events) || !abicore.EncodePollResultV1(memory, resultPtr, report, budget) {
				return errPollEncoding
			}
			return nil
		})
	})
	if err != nil {
		SetStatus(results, FromError(err))
		return
	}
	if pollErr != nil {
		if errors.Is(pollErr, errPollEncoding) {
			SetStatus(results, StatusIO)
		} else {
			SetStatus(results, FromError(pollErr))
		}
		return
	}
	SetStatus(results, FromProgress(progress))
}

func pollWorkUnits(budget readiness.Budget) uint64 {
	return uint64(budget.Scans) + uint64(budget.Events) + uint64(budget.ServiceAttempts)
}
