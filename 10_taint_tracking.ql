import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
        exists(MacroInvocation mi |
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
            this = mi.getExpr()
        )
    }
}

class Tracker extends TaintTracking::Configuration {
    Tracker() {
        this = "NetworkToMemFuncLength"
    }

    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap
    }

    override predicate isSink(DataFlow::Node sink) {
        exists(FunctionCall c | c.getTarget().getName() = "memcpy" and sink.asExpr() = c.getArgument(2))
    }
}

from Tracker tracker, DataFlow::PathNode source, DataFlow::PathNode sink
where tracker.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
