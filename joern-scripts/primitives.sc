import scala.collection.mutable
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*

object Primitives {

  final case class Finding(
    kind: String,
    method: String,
    line: Int,
    code: String,
    evidence: String
  )

  // -----------------------------
  // Config / helpers
  // -----------------------------
  private def ln(x: Option[Int]): Int = x.getOrElse(-1)

  private val AllocNames = Set(
    "malloc", "calloc", "realloc",
    "OPENSSL_malloc", "CRYPTO_malloc", "kmalloc"
  )

  private val FreeNames = Set(
    "free", "kfree", "g_free", "xfree",
    "OPENSSL_free", "CRYPTO_free"
  )

  private val CopyNames = Set(
    "memcpy", "memmove",
    "strcpy", "strncpy", "strcat",
    "sprintf", "vsprintf",
    "snprintf", "vsnprintf",
    "gets"
  )

  private val FsCheckNames = Set(
    "access", "stat", "lstat", "faccessat", "stat64", "_access"
  )

  private val FsUseNames = Set(
    "open", "fopen", "creat", "unlink", "rename"
  )

  private def idNames(e: Expression): Set[String] =
    e.ast.isIdentifier.name.l.toSet

  private def firstIdName(e: Expression): Option[String] =
    e.ast.isIdentifier.name.l.headOption

  private def firstArgCode(e: Expression): String =
    e.code

  private def methodFullName(m: Method): String = m.fullName

  private def isAllocCallExpr(e: Expression): Option[Call] =
    e.ast.isCall.l.find(c => AllocNames.contains(c.name))

  private def isFreeLikeCall(c: Call, freeWrappers: Set[String]): Boolean =
    FreeNames.contains(c.name) || freeWrappers.contains(c.name)

  /** Map: varName -> (allocLine, sizeExprCode) within a method. Keeps the latest alloc by line. */
  private def allocAssignments(m: Method): Map[String, (Int, String)] = {
    val assigns = m.call.l.filter(_.name == "<operator>.assignment")

    val pairs = assigns.flatMap { a =>
      val lhsOpt = firstIdName(a.argument(1))
      val rhsAllocOpt = isAllocCallExpr(a.argument(2))

      (lhsOpt, rhsAllocOpt) match {
        case (Some(v), Some(allocCall)) =>
          val sz = allocCall.argument.l.headOption.map(_.code).getOrElse(allocCall.code)
          Some(v -> (ln(a.lineNumber), sz))
        case _ =>
          None
      }
    }

    pairs
      .groupBy(_._1)
      .view
      .mapValues(xs => xs.map(_._2).maxBy(_._1))
      .toMap
  }

  /** Within a method, build an undirected alias graph from simple assignments: a=b. */
  private def aliasClosure(m: Method, seed: String, upToLine: Int): Set[String] = {
    val edges = m.call.l
      .filter(c => c.name == "<operator>.assignment" && ln(c.lineNumber) >= 0 && ln(c.lineNumber) <= upToLine)
      .flatMap { a =>
        val lhs = firstIdName(a.argument(1))
        val rhs = firstIdName(a.argument(2))
        (lhs, rhs) match {
          case (Some(x), Some(y)) if x.nonEmpty && y.nonEmpty => List((x, y), (y, x))
          case _ => Nil
        }
      }

    val adj = mutable.HashMap.empty[String, mutable.HashSet[String]]
    edges.foreach { case (u, v) =>
      val s = adj.getOrElseUpdate(u, mutable.HashSet.empty[String])
      s.add(v)
    }

    val seen = mutable.HashSet.empty[String]
    val q = mutable.ArrayDeque.empty[String]

    seen.add(seed)
    q.append(seed)

    while (q.nonEmpty) {
      val cur = q.removeHead()
      adj.get(cur).foreach { ns =>
        ns.foreach { n =>
          if (!seen.contains(n)) {
            seen.add(n)
            q.append(n)
          }
        }
      }
    }

    seen.toSet
  }

  private def freeWrapperNames(cpg: Cpg): Set[String] =
    cpg.method.l
      .filter(m => m.call.name.l.exists(FreeNames.contains))
      .map(_.name)
      .toSet

  // -----------------------------
  // 01. Heap metadata corruption (heap overflow-ish primitives)
  // Heuristic: heap alloc assigned to var + later unsafe copy into that var.
  // -----------------------------
  def heapMetadataCorrupt(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val allocs = allocAssignments(m)

      val suspiciousCopies = m.call.l
        .filter(c => CopyNames.contains(c.name))
        .flatMap { c =>
          val dstIds = c.argument.l.headOption.map(idNames).getOrElse(Set.empty)

          dstIds.toList.flatMap { dst =>
            allocs.get(dst).toList.flatMap { case (allocLine, sz) =>
              val cl = ln(c.lineNumber)
              if (allocLine >= 0 && cl >= 0 && cl > allocLine) {
                val ev = s"dst=$dst allocated at line=$allocLine sizeExpr=[$sz], then ${c.name} at line=$cl"
                Some(Finding("heap_metadata_corrupt", methodFullName(m), cl, c.code, ev))
              } else None
            }
          }
        }

      suspiciousCopies
    }.distinct
  }

  // -----------------------------
  // 02. Integer overflow in allocation
  // Heuristic: malloc/realloc size expression contains multiply/shift/large adds; calloc uses non-const factors.
  // -----------------------------
  def integerOverflowAlloc(cpg: Cpg): List[Finding] = {
    val allocCalls =
      cpg.call.l.filter(c => AllocNames.contains(c.name))

    allocCalls.flatMap { c =>
      val szCode = c.argument.l.map(_.code).mkString(", ")
      val hot =
        szCode.contains("*") || szCode.contains("<<") || szCode.contains("+") || szCode.contains("-")

      val hasVar = c.argument.ast.isIdentifier.name.l.nonEmpty
      val cl = ln(c.lineNumber)

      if (hot && hasVar) {
        val ev = s"alloc=${c.name} sizeArgs=[$szCode] contains arithmetic with identifiers"
        Some(Finding("integer_overflow_alloc", c.method.fullName, cl, c.code, ev))
      } else None
    }.distinct
  }

  // -----------------------------
  // 03. UAF (refcount / wrapper frees)
  // Heuristic:
  //  - treat free() and any function containing a free() call as freeing wrappers
  //  - if ptr (or alias) is used in calls AFTER the free-wrapper call line => suspicious
  // -----------------------------
  def uafRefcount(cpg: Cpg): List[Finding] = {
    val wrappers = freeWrapperNames(cpg)

    cpg.method.l.flatMap { m =>
      val calls = m.call.l.filter(c => isFreeLikeCall(c, wrappers) && ln(c.lineNumber) >= 0)

      calls.flatMap { freeCall =>
        val freeLine = ln(freeCall.lineNumber)

        // seed identifiers from *all* arguments for wrapper calls; for free(), arg(1) is most relevant
        val seedIds: Set[String] =
          if (FreeNames.contains(freeCall.name) && freeCall.argument.l.nonEmpty)
            idNames(freeCall.argument(1))
          else
            freeCall.argument.l.flatMap(idNames).toSet

        seedIds.toList.flatMap { seed =>
          val aliases = aliasClosure(m, seed, freeLine)

          // stop at first reassignment after free (best-effort)
          val firstRedef =
            m.call.l
              .filter(a => a.name == "<operator>.assignment" && ln(a.lineNumber) > freeLine)
              .filter(a => a.argument.l.headOption.exists(arg1 => idNames(arg1).contains(seed)))
              .map(a => ln(a.lineNumber))
              .sorted
              .headOption
              .getOrElse(-1)

          val usesAfterFree =
            m.call.l
              .filter(c => ln(c.lineNumber) > freeLine)
              .filter(c => firstRedef < 0 || ln(c.lineNumber) < firstRedef)
              .filterNot(c => isFreeLikeCall(c, wrappers))
              .filterNot(c => c.name == "<operator>.assignment") // filter out pure reassigns
              .filter { c =>
                c.argument.l.exists(arg => idNames(arg).exists(aliases.contains))
              }

          usesAfterFree.flatMap { use =>
            val ul = ln(use.lineNumber)
            if (ul >= 0) {
              val ev = s"freeLike=${freeCall.name} at line=$freeLine seeds=$seed aliases=${aliases.toList.sorted.mkString(",")}"
              Some(Finding("uaf_refcount", methodFullName(m), ul, use.code, ev))
            } else None
          }
        }
      }
    }.distinct
  }

  // -----------------------------
  // 04. Double free (including wrapper frees)
  // Heuristic: two free-like calls in same method on same arg-code.
  // -----------------------------
  def doubleFreeErrorPath(cpg: Cpg): List[Finding] = {
    val wrappers = freeWrapperNames(cpg)

    cpg.method.l.flatMap { m =>
      val freeCalls = m.call.l
        .filter(c => isFreeLikeCall(c, wrappers) && ln(c.lineNumber) >= 0)

      val groups = freeCalls.groupBy { c =>
        if (FreeNames.contains(c.name) && c.argument.l.nonEmpty) c.argument(1).code
        else c.argument.l.headOption.map(_.code).getOrElse(c.code)
      }

      groups.values.toList.flatMap { xs =>
        val ordered = xs.sortBy(c => ln(c.lineNumber))
        if (ordered.size >= 2) {
          val first = ordered.head
          ordered.tail.flatMap { df =>
            val ev = s"firstFreeLine=${ln(first.lineNumber)} firstFree=[${first.code}]"
            Some(Finding("double_free_error_path", methodFullName(m), ln(df.lineNumber), df.code, ev))
          }
        } else Nil
      }
    }.distinct
  }

  // -----------------------------
  // 05. Stack overflow / snprintf misuse
  // Heuristic:
  //  - flag sprintf/vsprintf/gets
  //  - flag vsnprintf/snprintf where return value flows into return/offset arithmetic (review-required)
  // -----------------------------
  def stackOverflowSnprintf(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val alwaysBad =
        m.call.l
          .filter(c => Set("sprintf", "vsprintf", "gets").contains(c.name))
          .map { c =>
            Finding("stack_overflow_snprintf", methodFullName(m), ln(c.lineNumber), c.code, s"unsafe call: ${c.name}")
          }

      val assigns = m.call.l.filter(_.name == "<operator>.assignment")

      val snprintfReturns = assigns.flatMap { a =>
        val lhs = firstIdName(a.argument(1))
        val rhs = a.argument(2).ast.isCall.l.find(c => Set("snprintf", "vsnprintf").contains(c.name))
        (lhs, rhs) match {
          case (Some(v), Some(call)) =>
            val line = ln(a.lineNumber)
            val retUses =
              m.ast.isReturn.l
                .filter(r => ln(r.lineNumber) > line)
                .filter(r => r.code.contains(v))

            if (retUses.nonEmpty) {
              Some(Finding(
                "stack_overflow_snprintf",
                methodFullName(m),
                line,
                a.code,
                s"snprintf return assigned to '$v' then used in return expr(s) without strong guarantees"
              ))
            } else None
          case _ => None
        }
      }

      (alwaysBad ++ snprintfReturns).distinct
    }.distinct
  }

  // -----------------------------
  // 06. Type confusion
  // Heuristic:
  //  - union-style access markers (Ghidra-ish): '->as.' / '.as.'
  //  - AND no obvious type-tag check in conditions (contains 'type' comparisons)
  // -----------------------------
  def typeConfusion(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val hasUnionAccess =
        m.ast.code.l.exists(s => s.contains("->as.") || s.contains(".as."))

      val hasTypeCheck =
        m.controlStructure.condition.code.l.exists { s =>
          val t = s.toLowerCase
          t.contains("type") && (t.contains("==") || t.contains("!="))
        }

      if (hasUnionAccess && !hasTypeCheck) {
        List(Finding(
          "type_confusion",
          methodFullName(m),
          ln(m.lineNumber),
          s"${m.name}(...)",
          "union-like access found but no obvious tag/type check in controlStructure conditions"
        ))
      } else Nil
    }.distinct
  }

  // -----------------------------
  // 07. TOCTOU race
  // Heuristic: filesystem check (access/stat/lstat) then later open/fopen/etc on same path expression.
  // -----------------------------
  def toctouRace(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val checks = m.call.l
        .filter(c => FsCheckNames.contains(c.name) && ln(c.lineNumber) >= 0)
        .flatMap { c =>
          val arg0 = c.argument.l.headOption.map(_.code)
          arg0.map(path => (path, ln(c.lineNumber), c.code))
        }

      val uses = m.call.l
        .filter(c => FsUseNames.contains(c.name) && ln(c.lineNumber) >= 0)
        .flatMap { c =>
          val arg0 = c.argument.l.headOption.map(_.code)
          arg0.map(path => (path, ln(c.lineNumber), c.code))
        }

      checks.flatMap { case (p, chkLine, chkCode) =>
        uses.filter { case (p2, useLine, _) => p2 == p && useLine > chkLine }
          .map { case (_, useLine, useCode) =>
            Finding(
              "toctou_race",
              methodFullName(m),
              useLine,
              useCode,
              s"check at line=$chkLine [$chkCode] then use on same path expr=[$p]"
            )
          }
      }
    }.distinct
  }

  // -----------------------------
  // 08. Uninitialized memory
  // Heuristic: memcpy(out, buf, CONST) where earlier memcpy(buf, in, varLen) and no memset(buf,0,CONST) in between.
  // -----------------------------
  def uninitMemory(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val memcpys = m.call.l.filter(_.name == "memcpy").filter(c => c.argument.l.size >= 3)

      val writesTo = memcpys.flatMap { c =>
        val dst = c.argument(1).code
        val sz  = c.argument(3).code
        Some((dst, ln(c.lineNumber), c.code, sz))
      }

      val readsFrom = memcpys.flatMap { c =>
        val src = c.argument(2).code
        val sz  = c.argument(3).code
        Some((src, ln(c.lineNumber), c.code, sz))
      }

      val memsets = m.call.l.filter(_.name == "memset").filter(c => c.argument.l.size >= 3)
        .map(c => (c.argument(1).code, ln(c.lineNumber)))

      readsFrom.flatMap { case (buf, readLine, readCode, readSz) =>
        // target pattern: read size is constant-ish and larger than earlier write size var
        val looksConst = readSz.forall(ch => ch.isDigit) || readSz.startsWith("0x")
        if (!looksConst) Nil
        else {
          val priorWrites = writesTo.filter { case (dst, wLine, _, _) => dst == buf && wLine >= 0 && wLine < readLine }
          val hasBetweenMemset = memsets.exists { case (b, ml) => b == buf && ml > priorWrites.map(_._2).maxOption.getOrElse(-1) && ml < readLine }

          // flag only if we saw a prior write with non-const size (best-effort)
          val priorVarSized = priorWrites.exists { case (_, _, _, wSz) =>
            !(wSz.forall(_.isDigit) || wSz.startsWith("0x"))
          }

          if (priorVarSized && !hasBetweenMemset) {
            val ev = s"read memcpy uses const size=$readSz from buf=[$buf] after a var-sized write; no memset(buf,0,$readSz) observed between"
            List(Finding("uninit_memory", methodFullName(m), readLine, readCode, ev))
          } else Nil
        }
      }
    }.distinct
  }

  // -----------------------------
  // 09. Protocol parser primitives
  // Heuristic A: uncontrolled recursion: method calls itself (depth+1 style) but depth check appears only after call (or missing).
  // -----------------------------
  def protocolParser(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val selfCalls = m.call.l.filter(c => c.name == m.name && ln(c.lineNumber) >= 0)
      if (selfCalls.isEmpty) Nil
      else {
        val depthChecks = m.controlStructure.condition.code.l
          .filter(s => s.toLowerCase.contains("depth") && (s.contains(">") || s.contains(">=") || s.contains("<") || s.contains("<=")))

        selfCalls.flatMap { sc =>
          val callLine = ln(sc.lineNumber)
          val hasPriorDepthCheck = m.controlStructure.l.exists { cs =>
            val csLine = ln(cs.lineNumber)
            csLine >= 0 && csLine < callLine && cs.condition.code.l.exists(s => s.toLowerCase.contains("depth"))
          }

          if (!hasPriorDepthCheck) {
            Some(Finding(
              "protocol_parser",
              methodFullName(m),
              callLine,
              sc.code,
              s"self-recursive call without an obvious prior depth bound check; consider DoS via deep nesting"
            ))
          } else None
        }
      }
    }.distinct
  }

  // -----------------------------
  // 10. Arch-specific bugs
  // Heuristic:
  //  - suspicious casts with unaligned pointer arithmetic (+1) into uint16_t*/uint32_t*
  //  - pointer truncation-style casts to int/uint32
  // -----------------------------
  def archSpecificBugs(cpg: Cpg): List[Finding] = {
    val casts = cpg.call.l.filter(_.name == "<operator>.cast")

    casts.flatMap { c =>
      val code = c.code
      val cl = ln(c.lineNumber)

      val unaligned =
        (code.contains("uint32_t") || code.contains("uint16_t")) &&
          (code.contains("+ 1") || code.contains("+1"))

      val ptrTrunc =
        (code.contains("(int)") || code.contains("(unsigned int)") || code.contains("(uint32_t)")) &&
          (code.contains("*") || code.contains("ptr") || code.contains("buffer") || code.contains("addr"))

      if (unaligned) {
        Some(Finding("arch_specific_bugs", c.method.fullName, cl, code, "cast looks like unaligned access (+1) into wide integer pointer type"))
      } else if (ptrTrunc) {
        Some(Finding("arch_specific_bugs", c.method.fullName, cl, code, "cast looks like pointer truncation / width mismatch risk across architectures"))
      } else None
    }.distinct
  }

  // -----------------------------
  // Runner / pretty-print
  // -----------------------------
  def runAll(cpg: Cpg): Map[String, List[Finding]] = {
    val res = Map(
      "01_heap_metadata_corrupt"      -> heapMetadataCorrupt(cpg),
      "02_integer_overflow_alloc"     -> integerOverflowAlloc(cpg),
      "03_uaf_refcount"               -> uafRefcount(cpg),
      "04_double_free_error_path"     -> doubleFreeErrorPath(cpg),
      "05_stack_overflow_snprintf"    -> stackOverflowSnprintf(cpg),
      "06_type_confusion"             -> typeConfusion(cpg),
      "07_toctou_race"                -> toctouRace(cpg),
      "08_uninit_memory"              -> uninitMemory(cpg),
      "09_protocol_parser"            -> protocolParser(cpg),
      "10_arch_specific_bugs"         -> archSpecificBugs(cpg)
    )

    println("")
    println("==== Primitive detections (summary) ====")
    res.foreach { case (k, xs) =>
      println(f"$k%-28s : ${xs.size}%d")
    }
    println("=======================================")
    println("")
    res
  }

  def show(findings: List[Finding], limit: Int = 50): Unit = {
    findings.take(limit).foreach { f =>
      println(s"[${f.kind}] ${f.method}:${f.line}")
      println(s"  code: ${f.code}")
      println(s"  ev  : ${f.evidence}")
      println("")
    }
  }
}
