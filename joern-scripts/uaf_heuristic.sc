import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, Identifier, Method, Expression}

object UafHeuristic {

  // Tune as needed
  val allocNames: Set[String] = Set(
    "malloc", "calloc", "realloc", "strdup", "strndup",
    "HeapAlloc",
    "kmalloc", "kzalloc", "kcalloc", "vmalloc"
  )

  val freeNames: Set[String] = Set(
    "free", "kfree", "HeapFree",
    "CRYPTO_free", "OPENSSL_free",
    "xfree"
  )

  // "use" operators (deref/field/index)
  val useOps: Set[String] = Set(
    "<operator>.indirection",
    "<operator>.fieldAccess",
    "<operator>.indirectFieldAccess",
    "<operator>.indexAccess",
    "<operator>.indirectIndexAccess"
  )

  private def idsInExpr(expr: AstNode): Set[String] =
    expr.ast.isIdentifier.name.toSet

  private def isLhsOfAssignment(id: Identifier): Boolean = {
    id.inCall
      .nameExact("<operator>.assignment")
      .argument(1)
      .ast.isIdentifier
      .exists(_.id == id.id)
  }

  private def overwrittenBetween(m: Method, names: Set[String], a: Int, b: Int): Boolean = {
    if (a < 0 || b < 0 || b <= a) return false

    m.ast.isCall
      .nameExact("<operator>.assignment")
      .filter(c => c.lineNumber.exists(ln => ln > a && ln <= b))
      .argument(1).ast.isIdentifier
      .name
      .exists(names.contains)
  }

  private def rhsHasAlloc(asg: Call): Boolean = {
    // IMPORTANT for your Joern: asg.argument(2).isCall is Boolean.
    // Use AST traversal to reach call nodes instead.
    asg.argument(2).ast.isCall.name.exists(allocNames.contains)
  }

  private def reallocatedBetween(m: Method, names: Set[String], a: Int, b: Int): Boolean = {
    if (a < 0 || b < 0 || b <= a) return false

    val assigns = m.ast.isCall
      .nameExact("<operator>.assignment")
      .filter(c => c.lineNumber.exists(ln => ln > a && ln <= b))
      .toList

    assigns.exists { asg =>
      val lhsNames = asg.argument(1).ast.isIdentifier.name.toSet
      lhsNames.exists(names.contains) && rhsHasAlloc(asg)
    }
  }

  private def allocatedBefore(m: Method, names: Set[String], freeLine: Int): Boolean = {
    if (freeLine < 0) return false

    m.ast.isCall
      .nameExact("<operator>.assignment")
      .filter(c => c.lineNumber.exists(_ < freeLine))
      .exists { asg =>
        val lhsNames = asg.argument(1).ast.isIdentifier.name.toSet
        lhsNames.exists(names.contains) && rhsHasAlloc(asg)
      }
  }

  // Simple alias closure using assignments before freeLine
  private def aliasClosureBefore(m: Method, seed: Set[String], freeLine: Int): Set[String] = {
    val assigns = m.ast.isCall
      .nameExact("<operator>.assignment")
      .filter(c => c.lineNumber.exists(_ <= freeLine))
      .toList

    val edges: List[(String, String)] = assigns.flatMap { asg =>
      val lhs = asg.argument(1).ast.isIdentifier.name.toList
      val rhs = asg.argument(2).ast.isIdentifier.name.toList
      for { l <- lhs; r <- rhs } yield (l, r)
    }

    var closure = seed
    var changed = true
    while (changed) {
      changed = false
      edges.foreach { case (l, r) =>
        if (closure.contains(r) && !closure.contains(l)) { closure += l; changed = true }
        if (closure.contains(l) && !closure.contains(r)) { closure += r; changed = true }
      }
    }
    closure
  }

  private def usesAfterFree(m: Method, names: Set[String], freeLine: Int): List[AstNode] = {
    // identifier uses (excluding LHS writes)
    val ids: List[AstNode] =
      m.ast.isIdentifier
        .filter(id => names.contains(id.name))
        .filter(id => id.lineNumber.exists(_ > freeLine))
        .filterNot(isLhsOfAssignment)
        .toList
        .map(_.asInstanceOf[AstNode])

    // deref/field/index operator uses
    val opUses: List[AstNode] =
      m.ast.isCall
        .filter(c => useOps.contains(c.name))
        .filter(c => c.lineNumber.exists(_ > freeLine))
        .filter(c => c.argument.ast.isIdentifier.name.exists(names.contains))
        .toList
        .map(_.asInstanceOf[AstNode])

    // passed as argument to other calls (exclude alloc/free)
    val argUses: List[AstNode] =
      m.ast.isCall
        .filter(c => c.lineNumber.exists(_ > freeLine))
        .filterNot(c => freeNames.contains(c.name))
        .filterNot(c => allocNames.contains(c.name))
        .filter(c => c.argument.ast.isIdentifier.name.exists(names.contains))
        .toList
        .map(_.asInstanceOf[AstNode])

    (ids ++ opUses ++ argUses).groupBy(_.id).values.map(_.head).toList
  }

  case class Finding(method: String, freeLine: Int, useLine: Int,
                     aliases: Set[String], freeCode: String, useCode: String)

  // Pass cpg explicitly (in scripts, `cpg` is not always in compile scope)
  def run(cpg: Cpg, maxFindings: Int = 200): Unit = {
    val findings = scala.collection.mutable.ArrayBuffer[Finding]()

    val frees: List[Call] =
      cpg.call
        .filter(c => freeNames.contains(c.name))
        .toList

    frees.foreach { freeCall =>
      val m: Method = freeCall.method
      if (m == null) return

      val freeLine = freeCall.lineNumber.getOrElse(-1)
      if (freeLine < 0) return

      val arg0: Expression = freeCall.argument(1)
      if (arg0 == null) return

      val seedNames = idsInExpr(arg0)
      if (seedNames.isEmpty) return

      val aliases = aliasClosureBefore(m, seedNames, freeLine)

      // reduce noise: require some alloc assigned before free
      if (!allocatedBefore(m, aliases, freeLine)) return

      val uses = usesAfterFree(m, aliases, freeLine)
      uses.foreach { useNode =>
        val useLine = useNode.lineNumber.getOrElse(-1)
        if (useLine > freeLine) {
          val overwritten = overwrittenBetween(m, aliases, freeLine, useLine)
          val reallocated = reallocatedBetween(m, aliases, freeLine, useLine)
          if (!overwritten && !reallocated) {
            findings += Finding(
              method = m.fullName,
              freeLine = freeLine,
              useLine = useLine,
              aliases = aliases,
              freeCode = freeCall.code,
              useCode = useNode.code
            )
          }
        }
      }
    }

    val out = findings.sortBy(f => (f.method, f.freeLine, f.useLine)).take(maxFindings).toList
    if (out.isEmpty) {
      println("[UAF] No findings (under current heuristics).")
      return
    }

    println(s"[UAF] Findings: ${out.size}")
    out.zipWithIndex.foreach { case (f, i) =>
      println("")
      println(s"--- [${i + 1}] ${f.method}")
      println(s"free @ line ${f.freeLine}: ${f.freeCode}")
      println(s"use  @ line ${f.useLine}: ${f.useCode}")
      println(s"aliases: ${f.aliases.toList.sorted.mkString(", ")}")
    }
  }
}
