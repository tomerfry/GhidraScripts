import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*

import scala.util.Try
import scala.util.matching.Regex
import scala.collection.mutable

object MemcorrPrimitivesV2 {

  // -------------------------
  // Model
  // -------------------------
  final case class Finding(
    rule: String,
    method: String,
    line: Int,
    code: String,
    details: String = "",
    severity: String = "MEDIUM"
  ) {
    override def toString: String = {
      val loc = if (line >= 0) s":$line" else ""
      val det = if (details.nonEmpty) s" // $details" else ""
      s"[$severity][$rule] $method$loc :: $code$det"
    }
  }

  // -------------------------
  // Helpers
  // -------------------------
  private def lnOpt(o: Option[Int]): Int = o.getOrElse(-1)
  private def lnCall(c: Call): Int = lnOpt(c.lineNumber)

  private def methodOfCall(c: Call): String =
    Option(c.method).map(_.fullName).getOrElse("<unknown-method>")

  private def argCode(c: Call, idx: Int): String =
    Try(Option(c.argument(idx)).map(_.code).getOrElse("")).getOrElse("")

  private def allArgCodes(c: Call): List[String] =
    c.argument.l.map(_.code)

  private val identRe: Regex = "^[A-Za-z_][A-Za-z0-9_]*$".r
  private def asSimpleIdent(code: String): Option[String] = code.trim match {
    case identRe() => Some(code.trim)
    case _ => None
  }

  private def isNumericLiteral(s: String): Boolean = {
    val t = s.trim
    t.matches("^[0-9]+$") || t.matches("^0x[0-9a-fA-F]+$") || t.matches("^'.'$")
  }

  // Extract identifiers from an expression
  private def extractIdents(code: String): Set[String] = {
    val pattern = "[A-Za-z_][A-Za-z0-9_]*".r
    pattern.findAllIn(code).toSet -- Set("if", "else", "while", "for", "return", "sizeof", "NULL", "void", "int", "char", "unsigned", "long", "short", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "size_t", "ulong", "uchar", "ushort", "byte", "word", "dword", "qword")
  }

  // -------------------------
  // NEW: Pattern 1 - Heartbleed-class: Length from buffer -> memcpy without bounds check
  // This is the KEY missing detection
  // -------------------------
  
  // Detect pointer dereference patterns that extract length values from buffers
  // Examples: *(ushort *)(p + 1), *(uint16_t *)ptr, p[1] << 8 | p[2]
  private val ptrDerefPatterns = List(
    "\\*\\s*\\([^)]*\\*\\s*\\)\\s*\\(".r,           // *(type *)(expr)
    "\\*\\s*\\([^)]*\\*\\s*\\)[A-Za-z_]".r,         // *(type *)var
    "\\[[0-9]+\\]\\s*<<".r,                          // p[N] << (byte extraction)
    "\\[[0-9]+\\]\\s*\\|".r,                         // p[N] | (byte combining)
    ">>\\s*8".r,                                     // >> 8 (byte swap pattern)
    "<<\\s*8".r                                      // << 8 (byte swap pattern)
  )
  
  private def looksLikeLengthExtraction(code: String): Boolean =
    ptrDerefPatterns.exists(_.findFirstIn(code).nonEmpty)

  private val copyFuncs = Set("memcpy", "memmove", "__memcpy_chk", "bcopy", "strncpy", "memcpy_s")
  private val allocFuncs = Set("malloc", "calloc", "realloc", "OPENSSL_malloc", "CRYPTO_malloc", "kmalloc", "kzalloc", "vmalloc")

  def heartbleedPattern(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val mCalls = m.call.l
      
      // Step 1: Find assignments where RHS looks like length extraction from a buffer
      val lengthExtractions = mCalls
        .filter(_.name == "<operator>.assignment")
        .flatMap { assign =>
          val lhs = Try(assign.argument(1).code).getOrElse("")
          val rhs = Try(assign.argument(2).code).getOrElse("")
          asSimpleIdent(lhs).filter(_ => looksLikeLengthExtraction(rhs) || rhs.contains("<<") || rhs.contains(">>"))
            .map(v => (v, (lnCall(assign), rhs)))  // 2-tuple: (String, (Int, String))
        }
        .toMap
      
      if (lengthExtractions.isEmpty) Nil
      else {
        // Step 2: Find memcpy calls where size argument involves these extracted lengths
        val copies = mCalls.filter(c => copyFuncs.contains(c.name))
        
        copies.flatMap { copyCall =>
          val copyLine = lnCall(copyCall)
          // Size is typically arg 3 for memcpy
          val sizeArg = if (copyCall.name == "bcopy") argCode(copyCall, 3) else argCode(copyCall, 3)
          val sizeIdents = extractIdents(sizeArg)
          
          // Check if any extracted length flows into the copy size
          val taintedByExtraction = lengthExtractions.keys.toSet.intersect(sizeIdents)
          
          if (taintedByExtraction.nonEmpty) {
            // Step 3: Check if there's a bounds validation BEFORE the copy
            // Look for comparisons involving the extracted length AND a "real" size/length parameter
            val hasValidation = mCalls
              .filter(c => lnCall(c) >= 0 && lnCall(c) < copyLine)
              .exists { c =>
                val code = c.code
                val isComparison = code.contains("<=") || code.contains(">=") || code.contains("<") || code.contains(">")
                val involvesTainted = taintedByExtraction.exists(code.contains)
                // Look for comparison with actual message/buffer length
                val involvesRealLen = code.contains("msg_len") || code.contains("actual") || 
                  code.contains("recv") || code.contains("read") || code.contains("n_bytes") ||
                  code.contains("buf_len") || code.contains("data_len") || code.contains("pkt_len")
                isComparison && involvesTainted && involvesRealLen
              }
            
            // Also check control structure conditions
            val hasControlValidation = m.controlStructure.l.exists { cs =>
              val csLine = lnOpt(cs.lineNumber)
              csLine >= 0 && csLine < copyLine && {
                val condCode = cs.condition.code.l.mkString(" ")
                val involvesTainted = taintedByExtraction.exists(condCode.contains)
                val involvesRealLen = condCode.contains("msg_len") || condCode.contains("len") ||
                  condCode.contains("size") || condCode.contains("actual")
                involvesTainted && involvesRealLen && 
                  (condCode.contains("<=") || condCode.contains(">=") || condCode.contains("<") || condCode.contains(">"))
              }
            }
            
            if (!hasValidation && !hasControlValidation) {
              val extractionInfo = taintedByExtraction.map(v => 
                lengthExtractions.get(v).map(t => s"$v extracted at line ${t._1}").getOrElse(v)
              ).mkString(", ")
              Some(Finding(
                "HEARTBLEED_CLASS",
                m.fullName,
                copyLine,
                copyCall.code,
                s"Length from buffer ($extractionInfo) flows to ${copyCall.name} size without apparent bounds validation against actual data length",
                "HIGH"
              ))
            } else None
          } else None
        }
      }
    }.distinct.sortBy(f => (f.method, f.line))
  }

  // -------------------------
  // NEW: Pattern 2 - Allocation size from untrusted source without validation
  // -------------------------
  def untrustedAllocSize(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val mCalls = m.call.l
      
      // Find length extractions (same as above)
      val lengthExtractions = mCalls
        .filter(_.name == "<operator>.assignment")
        .flatMap { assign =>
          val lhs = Try(assign.argument(1).code).getOrElse("")
          val rhs = Try(assign.argument(2).code).getOrElse("")
          asSimpleIdent(lhs).filter(_ => looksLikeLengthExtraction(rhs) || rhs.contains("<<") || rhs.contains(">>"))
            .map(v => (v, lnCall(assign)))
        }
        .toMap
      
      if (lengthExtractions.isEmpty) Nil
      else {
        val allocs = mCalls.filter(c => allocFuncs.contains(c.name))
        
        allocs.flatMap { allocCall =>
          val allocLine = lnCall(allocCall)
          val sizeArg = argCode(allocCall, 1)
          val sizeIdents = extractIdents(sizeArg)
          
          val taintedByExtraction = lengthExtractions.keys.toSet.intersect(sizeIdents)
          
          if (taintedByExtraction.nonEmpty) {
            // Check for integer overflow protection or bounds check
            val hasOverflowCheck = mCalls
              .filter(c => lnCall(c) >= 0 && lnCall(c) < allocLine)
              .exists { c =>
                val code = c.code.toLowerCase
                // Common overflow check patterns
                code.contains("overflow") || code.contains("max_") || code.contains("_max") ||
                  (code.contains("/") && taintedByExtraction.exists(code.contains)) ||
                  (code.contains("if") && code.contains(">") && taintedByExtraction.exists(code.contains))
              }
            
            if (!hasOverflowCheck) {
              Some(Finding(
                "UNTRUSTED_ALLOC_SIZE",
                m.fullName,
                allocLine,
                allocCall.code,
                s"Allocation size derived from buffer-extracted value (${taintedByExtraction.mkString(", ")}); potential integer overflow or excessive allocation",
                "MEDIUM"
              ))
            } else None
          } else None
        }
      }
    }.distinct.sortBy(f => (f.method, f.line))
  }

  // -------------------------
  // NEW: Pattern 3 - Copy size mismatch (src vs claimed)
  // Detect when copy uses a "claimed" size but source buffer may be smaller
  // -------------------------
  def copySizeMismatch(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val copies = m.call.l.filter(c => copyFuncs.contains(c.name))
      
      copies.flatMap { copyCall =>
        val copyLine = lnCall(copyCall)
        val srcArg = argCode(copyCall, 2)  // source buffer
        val sizeArg = argCode(copyCall, 3) // size
        
        val srcIdents = extractIdents(srcArg)
        val sizeIdents = extractIdents(sizeArg)
        
        // Flag if size comes from a different "family" than source
        // e.g., copying from 'p' but size comes from 'payload' extracted from p
        val srcBase = srcIdents.headOption.getOrElse("")
        val sizeVars = sizeIdents.filterNot(isNumericLiteral)
        
        // Check if there's a parameter that should constrain the copy (like msg_len)
        val methodParams = m.parameter.l.map(_.name).toSet
        val sizeRelatedParams = methodParams.filter(p => 
          p.contains("len") || p.contains("size") || p.contains("count") || p.contains("n"))
        
        // If method has a size/len parameter but it's not used to constrain the copy
        if (sizeRelatedParams.nonEmpty && !sizeIdents.exists(sizeRelatedParams.contains)) {
          // Check if there's validation earlier
          val hasValidation = m.controlStructure.condition.code.l.exists { cond =>
            sizeRelatedParams.exists(cond.contains) && sizeVars.exists(cond.contains)
          }
          
          if (!hasValidation && sizeVars.nonEmpty) {
            Some(Finding(
              "COPY_SIZE_MISMATCH",
              m.fullName,
              copyLine,
              copyCall.code,
              s"Copy size ($sizeArg) not validated against available size params (${sizeRelatedParams.mkString(", ")})",
              "MEDIUM"
            ))
          } else None
        } else None
      }
    }.distinct.sortBy(f => (f.method, f.line))
  }

  // -------------------------
  // NEW: Pattern 4 - Network byte order operations without length validation
  // ntohs/ntohl on packet data that flows to size calculations
  // -------------------------
  private val byteOrderFuncs = Set("ntohs", "ntohl", "htons", "htonl", "be16toh", "be32toh", "le16toh", "le32toh")
  private val byteSwapPatterns = List(
    "<<\\s*8\\s*\\|".r,      // x << 8 | y
    "\\|.*<<\\s*8".r,        // x | y << 8  
    ">>\\s*8".r              // x >> 8
  )

  def networkByteOrderTaint(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val mCalls = m.call.l
      
      // Find byte order conversions or manual byte swaps
      val byteOrderOps = mCalls.flatMap { c =>
        if (byteOrderFuncs.contains(c.name)) {
          Some((c.code, lnCall(c), "function"))
        } else if (c.name == "<operator>.assignment") {
          val rhs = Try(c.argument(2).code).getOrElse("")
          if (byteSwapPatterns.exists(_.findFirstIn(rhs).nonEmpty)) {
            val lhs = Try(c.argument(1).code).getOrElse("")
            asSimpleIdent(lhs).map(v => (v, lnCall(c), "swap"))
          } else None
        } else None
      }
      
      if (byteOrderOps.isEmpty) Nil
      else {
        // Track which variables hold byte-swapped values
        val swappedVars = byteOrderOps.flatMap {
          case (code, _, "function") => extractIdents(code).headOption
          case (varName, _, "swap") => Some(varName)
          case _ => None
        }.toSet
        
        // Find uses in allocation or copy sizes
        val dangerousUses = mCalls.filter { c =>
          val isAlloc = allocFuncs.contains(c.name)
          val isCopy = copyFuncs.contains(c.name)
          if (isAlloc || isCopy) {
            val sizeArg = if (isCopy) argCode(c, 3) else argCode(c, 1)
            val sizeIdents = extractIdents(sizeArg)
            swappedVars.intersect(sizeIdents).nonEmpty
          } else false
        }
        
        dangerousUses.flatMap { c =>
          val isCopy = copyFuncs.contains(c.name)
          val sizeArg = if (isCopy) argCode(c, 3) else argCode(c, 1)
          
          // Check for bounds validation
          val useLine = lnCall(c)
          val hasValidation = m.controlStructure.l.exists { cs =>
            val csLine = lnOpt(cs.lineNumber)
            csLine >= 0 && csLine < useLine && {
              val cond = cs.condition.code.l.mkString(" ")
              swappedVars.exists(cond.contains) && 
                (cond.contains("<=") || cond.contains("<") || cond.contains(">=") || cond.contains(">"))
            }
          }
          
          if (!hasValidation) {
            Some(Finding(
              "NETWORK_BYTE_ORDER_TAINT",
              m.fullName,
              useLine,
              c.code,
              s"Network byte order value flows to ${c.name} size ($sizeArg) without bounds check",
              "HIGH"
            ))
          } else None
        }
      }
    }.distinct.sortBy(f => (f.method, f.line))
  }

  // -------------------------
  // Improved: Overflow sinks with better taint tracking
  // -------------------------
  private val alwaysBad = Seq("strcpy", "strcat", "gets", "sprintf", "vsprintf")
  private val oftenBad = Seq("memcpy", "memmove", "strncpy", "snprintf", "vsnprintf", "__memcpy_chk")

  def overflowSinks(cpg: Cpg): List[Finding] = {
    val hard = cpg.call.nameExact(alwaysBad*).l.map { c =>
      Finding("OVERFLOW_SINK", methodOfCall(c), lnCall(c), c.code, "unbounded/unsafe libc sink", "HIGH")
    }

    val soft = cpg.call.nameExact(oftenBad*).l.flatMap { c =>
      val (idx, label) = c.name match {
        case "memcpy" | "memmove" | "strncpy" | "__memcpy_chk" => (3, "size arg #3")
        case "snprintf" | "vsnprintf" => (2, "size arg #2")
        case _ => (3, "size arg")
      }
      val sz = argCode(c, idx)
      
      // More comprehensive check for suspicious size expressions
      val suspicious = sz.nonEmpty && !isNumericLiteral(sz) && {
        val hasArithmetic = sz.contains("*") || sz.contains("+") || sz.contains("-") || sz.contains("<<")
        val hasIdentifier = extractIdents(sz).nonEmpty
        hasArithmetic || hasIdentifier
      }

      if (suspicious)
        Some(Finding("OVERFLOW_SINK", methodOfCall(c), lnCall(c), c.code, s"variable $label = $sz", "MEDIUM"))
      else None
    }

    (hard ++ soft).sortBy(f => (f.method, f.line))
  }

  // -------------------------
  // Keep existing detectors (improved)
  // -------------------------
  private val freeApis = Seq("free", "kfree", "vfree", "OPENSSL_free", "CRYPTO_free")

  def useAfterFree(cpg: Cpg): List[Finding] = {
    val frees = cpg.call.nameExact(freeApis*).l

    frees.flatMap { fc =>
      val m = fc.method
      val freeLine = lnCall(fc)
      val arg0 = asSimpleIdent(argCode(fc, 1))

      arg0.toList.flatMap { name =>
        val laterCalls = m.ast.isCall.l
          .filter(c => lnCall(c) > freeLine)
          .filter(c => !freeApis.contains(c.name))
          .filter(c => c.code.contains(name))

        laterCalls.take(3).map { use =>
          Finding("UAF", m.fullName, lnCall(use), use.code, s"use of freed '$name' after free@$freeLine", "HIGH")
        }
      }
    }.sortBy(f => (f.method, f.line))
  }

  def doubleFree(cpg: Cpg): List[Finding] = {
    val frees = cpg.call.nameExact(freeApis*).l

    frees
      .flatMap(fc => asSimpleIdent(argCode(fc, 1)).map(n => (fc.method.fullName, n, fc)))
      .groupBy { case (m, n, _) => (m, n) }
      .toList
      .flatMap { case ((m, name), lst) =>
        val calls = lst.map(_._3).sortBy(lnCall)
        if (calls.size >= 2) {
          val a = calls.head
          val b = calls(1)
          val aLine = lnCall(a)
          val bLine = lnCall(b)
          
          val assigns = a.method.ast.isCall.l
            .filter(c => c.name == "<operator>.assignment")
            .filter(c => lnCall(c) > aLine && lnCall(c) < bLine)
            .map(_.code)

          val nullified = assigns.exists(code => code.contains(name) && (code.contains("= 0") || code.contains("= NULL")))
          if (!nullified) {
            Some(Finding("DOUBLE_FREE", m, bLine, b.code, s"second free of '$name' (first@$aLine)", "HIGH"))
          } else None
        } else None
      }
      .sortBy(f => (f.method, f.line))
  }

  // -------------------------
  // Runner
  // -------------------------
  private def banner(title: String, n: Int): Unit = {
    println()
    println("=" * 90)
    println(s"$title: $n candidate(s)")
    println("=" * 90)
  }

  private def show(findings: List[Finding]): Unit =
    findings.foreach(f => println(f.toString))

  def runAll(cpg: Cpg): Map[String, List[Finding]] = {
    val results = Map(
      "heartbleed_class" -> heartbleedPattern(cpg),
      "untrusted_alloc_size" -> untrustedAllocSize(cpg),
      "copy_size_mismatch" -> copySizeMismatch(cpg),
      "network_byte_order_taint" -> networkByteOrderTaint(cpg),
      "overflow_sinks" -> overflowSinks(cpg),
      "use_after_free" -> useAfterFree(cpg),
      "double_free" -> doubleFree(cpg)
    )
    
    println("\n" + "=" * 90)
    println("MemcorrPrimitivesV2 - Enhanced Memory Corruption Detection")
    println("=" * 90)
    
    results.foreach { case (name, findings) =>
      banner(name, findings.size)
      show(findings)
    }
    
    println("\n" + "=" * 50)
    println("SUMMARY")
    println("=" * 50)
    results.foreach { case (name, findings) =>
      val highCount = findings.count(_.severity == "HIGH")
      val medCount = findings.count(_.severity == "MEDIUM")
      println(f"$name%-30s : ${findings.size}%3d findings ($highCount HIGH, $medCount MEDIUM)")
    }
    
    results
  }
}