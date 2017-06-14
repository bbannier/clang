#include "ClangSACheckers.h"
#include "clang/AST/ExprCXX.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {

struct OptionState {
  enum Kind { UNKNOWN, SOME, NONE };
  Kind K = UNKNOWN;

  OptionState(Kind k) : K(k) {}

  static OptionState Some() { return SOME; }
  static OptionState None() { return NONE; }

  friend bool operator==(const OptionState &lhs, const OptionState &rhs) {
    return lhs.K == rhs.K;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(K); }
};

class MesosOptionChecker : public Checker<check::PreCall, check::PostCall> {
  std::unique_ptr<BugType> BT_isNone{
      new BugType(this, "get called on empty Option", "Mesos-related checks")};

  mutable std::unique_ptr<BugType> BT_isUnknown{new BugType(
      this, "unchecked use of Option value", "Mesos-related checks")};

public:
  void checkPreCall(const CallEvent &CE, CheckerContext &C) const;
  void checkPostCall(const CallEvent &CE, CheckerContext &C) const;

private:
  void handleGet(const CallEvent &CE, CheckerContext &C) const;
};

} // end anonymous namespace

/// The state of the checker is a map from tracked option symbols to their
/// state. Let's store it in the ProgramState.
REGISTER_MAP_WITH_PROGRAMSTATE(OptionMap, const MemRegion *, OptionState);

namespace {
const CXXMethodDecl *getMemberFunction(const StringRef &ClassName,
                                       const CallEvent &CE) {
  if (CE.getKind() != CallEventKind::CE_CXXMember) {
    return {};
  }

  const CXXMethodDecl *MD =
      dyn_cast_or_null<CXXMethodDecl>(CE.getDecl()->getAsFunction());
  if (!MD) {
    return {};
  }

  const CXXRecordDecl *RD = MD->getParent();
  if (!RD) {
    return {};
  }

  if (RD->getName() != ClassName) {
    return {};
  }

  return MD;
}

void handleMemberObserver(const CallEvent &CE, CheckerContext &C,
                          OptionState TrueState, OptionState FalseState) {
  ProgramStateRef State = C.getState();
  const LocationContext *LC = C.getLocationContext();

  const CXXMemberCallExpr *MCE =
      dyn_cast_or_null<CXXMemberCallExpr>(CE.getOriginExpr());
  assert(MCE);
  const Expr *E = MCE->getImplicitObjectArgument();
  assert(E);
  const MemRegion *MR = State->getSVal(E, LC).getAsRegion();

  SVal CallReturnValue = CE.getReturnValue();
  Optional<DefinedOrUnknownSVal> DVal =
      CallReturnValue.getAs<DefinedOrUnknownSVal>();
  if (!DVal) {
    assert(false);
    return; // FIXME(bbannier): why?
  }

  ProgramStateRef TrueCase, FalseCase;
  std::tie(TrueCase, FalseCase) = State->assume(*DVal);

  if (TrueCase) {
    TrueCase = TrueCase->set<OptionMap>(MR, TrueState);
    C.addTransition(TrueCase);
  }

  if (FalseCase) {
    FalseCase = FalseCase->set<OptionMap>(MR, FalseState);
    C.addTransition(FalseCase);
  }
}
} // namespace

void MesosOptionChecker::checkPostCall(const CallEvent &CE,
                                       CheckerContext &C) const {
  const CXXMethodDecl *MD = getMemberFunction("Option", CE);
  if (!MD) {
    return;
  }

  if (MD->getName() == "isSome") {
    handleMemberObserver(CE, C, OptionState::Some(), OptionState::None());
  } else if (MD->getName() == "isNone") {
    handleMemberObserver(CE, C, OptionState::None(), OptionState::Some());
  }
}

void MesosOptionChecker::checkPreCall(const CallEvent &CE,
                                      CheckerContext &C) const {
  const CXXMethodDecl *MD = getMemberFunction("Option", CE);
  if (!MD) {
    return;
  }

  if (MD->getName() == "get") {
    handleGet(CE, C);
  }
}
void MesosOptionChecker::handleGet(const CallEvent &CE,
                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LC = C.getLocationContext();

  const CXXMemberCallExpr *MCE =
      dyn_cast_or_null<CXXMemberCallExpr>(CE.getOriginExpr());
  assert(MCE);
  const Expr *E = MCE->getImplicitObjectArgument();
  assert(E);
  const MemRegion *MR = State->getSVal(E, LC).getAsRegion();
  assert(MR);
  const OptionState *OS = State->get<OptionMap>(MR);

  const bool isUnknown = !OS;
  const bool isNone = OS && OS->K == OptionState::NONE;

  if (!isUnknown && !isNone) {
    return;
  }

  ExplodedNode *N = C.generateErrorNode();
  if (!N) {
    return;
  }

  BugType *BT = nullptr;

  if (isUnknown) {
    BT = BT_isUnknown.get();
  } else if (isNone) {
    BT = BT_isNone.get();
  }
  assert(BT);

  std::unique_ptr<BugReport> report =
      llvm::make_unique<BugReport>(*BT, BT->getName(), N);
  report->addRange(CE.getSourceRange());
  C.emitReport(std::move(report));

  C.generateSink(State, C.getPredecessor());
}

void ento::registerMesosOptionChecker(CheckerManager &mgr) {
  mgr.registerChecker<MesosOptionChecker>();
}
