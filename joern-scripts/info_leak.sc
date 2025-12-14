import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*

import scala.util.Try
import scala.collection.mutable

/**
 * HeartbleedDetector - Specifically targets CVE-2014-0160 class vulnerabilities
 * 
 * The Heartbleed pattern:
 * 1. Read a length value from an untrusted buffer (network packet)
 * 2. Use that length to allocate memory and/or copy data
 * 3. MISSING: Validate the claimed length against actual received data size
 * 
 * This results in reading beyond the actual packet data into adjacent memory (heap over-read).
 */
object HeartbleedDetector {

  case class Finding(
    pattern: String,
    method: String,
    line: Int,
    code: String,
    explanation: String,
    confidence: String = "MEDIUM"
  )

  private def ln(o: Option[Int]): Int = o.getOrElse(-1)

  private def argCode(c: Call, idx: Int): String =
    Try(c.argument(idx).code).getOrElse("")

  private def extractIdentifiers(code: String): Set[String] = {
    val reserved = Set("if", "else", "while", "for", "return", "sizeof", "NULL", 
      "void", "int", "char", "unsigned", "long", "short", "uint8_t", "uint16_t", 
      "uint32_t", "uint64_t", "size_t", "ulong", "uchar", "ushort", "true", "false")
    "[A-Za-z_][A-Za-z0-9_]*".r.findAllIn(code).toSet -- reserved
  }

  // Core allocation/copy functions
  private val allocFuncs = Set("malloc", "calloc", "realloc", "kmalloc", "kzalloc", 
    "OPENSSL_malloc", "CRYPTO_malloc", "vmalloc", "g_malloc", "av_malloc")
  
  private val copyFuncs = Set("memcpy", "memmove", "__memcpy_chk", "bcopy", "memcpy_s",
    "strncpy", "strlcpy", "__builtin_memcpy")

  /**
   * Pattern 1: Length Field Extraction
   * Detect when a value is extracted from a buffer via pointer cast/dereference
   * Examples:
   *   - *(ushort *)(p + 1)
   *   - *(uint16_t *)ptr  
   *   - p[0] << 8 | p[1]
   *   - ntohs(*(uint16_t *)(buf + offset))
   */
  def findLengthExtractions(m: Method): Map[String, (Int, String)] = {
    val result = mutable.Map[String, (Int, String)]()
    
    m.call.l.filter(_.name == "<operator>.assignment").foreach { assign =>
      val lhs = Try(assign.argument(1).code.trim).getOrElse("")
      val rhs = Try(assign.argument(2).code).getOrElse("")
      val line = ln(assign.lineNumber)
      
      // Check if RHS looks like buffer extraction
      val isBufferExtraction = 
        // Cast + deref: *(type *)(ptr + N) or *(type *)ptr
        (rhs.contains("*") && rhs.contains("(") && (rhs.contains("+") || rhs.matches(".*\\*\\s*\\([^)]+\\*\\s*\\)[A-Za-z].*"))) ||
        // Array access with bit manipulation: buf[N] << 8 | buf[M]  
        (rhs.contains("[") && (rhs.contains("<<") || rhs.contains("|") || rhs.contains(">>"))) ||
        // Byte swap patterns
        (rhs.contains("<<") && rhs.contains(">>") && rhs.contains("|")) ||
        // Direct cast dereference
        rhs.matches(".*\\*\\s*\\([^)]*\\*.*\\).*")
      
      if (isBufferExtraction && lhs.matches("[A-Za-z_][A-Za-z0-9_]*")) {
        result(lhs) = (line, rhs)
      }
    }
    result.toMap
  }

  /**
   * Pattern 2: Propagation through byte-swap operations
   * Track variables that derive from extracted lengths via ntohs-style operations
   */
  def findByteSwapDerivatives(m: Method, extracted: Map[String, (Int, String)]): Map[String, (Int, String)] = {
    val result = mutable.Map[String, (Int, String)]()
    result ++= extracted
    
    m.call.l.filter(_.name == "<operator>.assignment").sortBy(c => ln(c.lineNumber)).foreach { assign =>
      val lhs = Try(assign.argument(1).code.trim).getOrElse("")
      val rhs = Try(assign.argument(2).code).getOrElse("")
      val line = ln(assign.lineNumber)
      
      if (lhs.matches("[A-Za-z_][A-Za-z0-9_]*")) {
        val rhsIdents = extractIdentifiers(rhs)
        
        // If RHS uses an extracted variable in byte-swap pattern
        val usesExtracted = rhsIdents.exists(result.contains)
        val isByteSwap = rhs.contains("<<") || rhs.contains(">>") || rhs.contains("|") || 
          rhs.contains("ntohs") || rhs.contains("ntohl") || rhs.contains("be16toh") || rhs.contains("be32toh")
        
        if (usesExtracted && isByteSwap) {
          val srcVar = rhsIdents.find(result.contains).get
          result(lhs) = (line, s"derived from $srcVar: $rhs")
        }
        
        // Also track simple assignments: a = b where b is tainted
        val directCopy = rhsIdents.exists(result.contains) && rhsIdents.size == 1
        if (directCopy && !result.contains(lhs)) {
          val srcVar = rhsIdents.head
          result(lhs) = (line, s"copy of $srcVar")
        }
      }
    }
    result.toMap
  }

  /**
   * Pattern 3: Size calculation from tainted value
   * Track when allocation size is computed from tainted length
   */
  def findSizeCalculations(m: Method, tainted: Map[String, (Int, String)]): Map[String, (Int, String)] = {
    val result = mutable.Map[String, (Int, String)]()
    result ++= tainted
    
    m.call.l.filter(_.name == "<operator>.assignment").sortBy(c => ln(c.lineNumber)).foreach { assign =>
      val lhs = Try(assign.argument(1).code.trim).getOrElse("")
      val rhs = Try(assign.argument(2).code).getOrElse("")
      val line = ln(assign.lineNumber)
      
      if (lhs.matches("[A-Za-z_][A-Za-z0-9_]*")) {
        val rhsIdents = extractIdentifiers(rhs)
        val usesT = rhsIdents.exists(result.contains)
        val isCalc = rhs.contains("+") || rhs.contains("*") || rhs.contains("sizeof")
        
        if (usesT && isCalc && !result.contains(lhs)) {
          val srcVars = rhsIdents.filter(result.contains).mkString(", ")
          result(lhs) = (line, s"size calc from $srcVars: $rhs")
        }
      }
    }
    result.toMap
  }

  /**
   * Check if there's validation comparing tainted value against actual length
   */
  def hasLengthValidation(m: Method, taintedVars: Set[String], beforeLine: Int): Boolean = {
    // Look for comparisons in control structures
    m.controlStructure.l.exists { cs =>
      val csLine = ln(cs.lineNumber)
      csLine >= 0 && csLine < beforeLine && {
        val conditions = cs.condition.code.l.mkString(" ")
        val hasTaintedVar = taintedVars.exists(conditions.contains)
        val hasComparison = conditions.contains("<=") || conditions.contains(">=") || 
          conditions.contains("<") || conditions.contains(">")
        // Look for comparison against actual length parameter
        val hasLenParam = conditions.contains("msg_len") || conditions.contains("len") ||
          conditions.contains("size") || conditions.contains("n_") || conditions.contains("actual") ||
          conditions.contains("recv") || conditions.contains("read") || conditions.contains("avail")
        
        hasTaintedVar && hasComparison && hasLenParam
      }
    }
  }

  /**
   * Main detection: Find vulnerable memcpy/allocation patterns
   */
  def detect(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val findings = mutable.ListBuffer[Finding]()
      
      // Step 1: Find length extractions from buffers
      val extracted = findLengthExtractions(m)
      
      if (extracted.nonEmpty) {
        // Step 2: Track derivatives (byte swaps, copies)
        val withSwaps = findByteSwapDerivatives(m, extracted)
        
        // Step 3: Track size calculations
        val allTainted = findSizeCalculations(m, withSwaps)
        
        // Step 4: Find dangerous uses (memcpy size, malloc size)
        m.call.l.foreach { call =>
          val callLine = ln(call.lineNumber)
          
          if (copyFuncs.contains(call.name)) {
            // Check memcpy size argument (arg 3)
            val sizeArg = argCode(call, 3)
            val sizeIdents = extractIdentifiers(sizeArg)
            val taintedUsed = sizeIdents.intersect(allTainted.keySet)
            
            if (taintedUsed.nonEmpty) {
              val hasValidation = hasLengthValidation(m, taintedUsed, callLine)
              
              if (!hasValidation) {
                val taintInfo = taintedUsed.map(v => 
                  allTainted.get(v).map(t => s"$v (line ${t._1}: ${t._2.take(50)})").getOrElse(v)
                ).mkString("; ")
                
                findings += Finding(
                  "HEARTBLEED_MEMCPY",
                  m.fullName,
                  callLine,
                  call.code,
                  s"Buffer-extracted length ($taintInfo) used in ${call.name} size without bounds validation",
                  "HIGH"
                )
              }
            }
          }
          
          if (allocFuncs.contains(call.name)) {
            val sizeArg = argCode(call, 1)
            val sizeIdents = extractIdentifiers(sizeArg)
            val taintedUsed = sizeIdents.intersect(allTainted.keySet)
            
            if (taintedUsed.nonEmpty) {
              val hasValidation = hasLengthValidation(m, taintedUsed, callLine)
              
              if (!hasValidation) {
                // For allocation, also check for integer overflow guards
                val hasOverflowCheck = m.call.l.exists { c =>
                  val cLine = ln(c.lineNumber)
                  cLine >= 0 && cLine < callLine && {
                    val code = c.code.toLowerCase
                    (code.contains("max") || code.contains("overflow") || code.contains("limit")) &&
                      taintedUsed.exists(code.toLowerCase.contains)
                  }
                }
                
                if (!hasOverflowCheck) {
                  findings += Finding(
                    "HEARTBLEED_ALLOC",
                    m.fullName,
                    callLine,
                    call.code,
                    s"Buffer-extracted length used in allocation size without bounds/overflow check",
                    "MEDIUM"
                  )
                }
              }
            }
          }
        }
      }
      
      findings.toList
    }.distinct
  }

  /**
   * Supplementary: Check for functions that have length parameters but don't use them
   */
  def unusedLengthParams(cpg: Cpg): List[Finding] = {
    cpg.method.l.flatMap { m =>
      val params = m.parameter.l
      val lenParams = params.filter { p =>
        val name = p.name.toLowerCase
        name.contains("len") || name.contains("size") || name.contains("count") || 
          name == "n" || name.contains("nbytes")
      }
      
      if (lenParams.nonEmpty) {
        val hasCopy = m.call.l.exists(c => copyFuncs.contains(c.name))
        val hasAlloc = m.call.l.exists(c => allocFuncs.contains(c.name))
        
        if (hasCopy || hasAlloc) {
          val lenParamNames = lenParams.map(_.name).toSet
          
          // Check if len params are used in copy/alloc operations
          val copyAllocs = m.call.l.filter(c => copyFuncs.contains(c.name) || allocFuncs.contains(c.name))
          val usesLenParam = copyAllocs.exists { c =>
            val args = (1 to 4).map(i => argCode(c, i)).mkString(" ")
            lenParamNames.exists(args.contains)
          }
          
          // Check if len params are used in any validation
          val usedInValidation = m.controlStructure.condition.code.l.exists { cond =>
            lenParamNames.exists(cond.contains)
          }
          
          if (!usesLenParam && !usedInValidation) {
            Some(Finding(
              "UNUSED_LEN_PARAM",
              m.fullName,
              ln(m.lineNumber),
              m.signature,
              s"Length params (${lenParamNames.mkString(", ")}) present but not used in copy/alloc bounds checks",
              "MEDIUM"
            ))
          } else None
        } else None
      } else None
    }.distinct
  }

  def runAll(cpg: Cpg): Unit = {
    println("\n" + "=" * 80)
    println("HeartbleedDetector - CVE-2014-0160 Class Vulnerability Scanner")
    println("=" * 80)
    
    val main = detect(cpg)
    val unused = unusedLengthParams(cpg)
    
    println(s"\n[HEARTBLEED PATTERN] Found ${main.size} candidate(s):")
    main.foreach { f =>
      println(s"  [${f.confidence}] ${f.method}:${f.line}")
      println(s"    Code: ${f.code.take(80)}...")
      println(s"    Issue: ${f.explanation}")
      println()
    }
    
    println(s"\n[UNUSED LENGTH PARAMS] Found ${unused.size} candidate(s):")
    unused.foreach { f =>
      println(s"  [${f.confidence}] ${f.method}:${f.line}")
      println(s"    Issue: ${f.explanation}")
      println()
    }
    
    val total = main.size + unused.size
    val high = main.count(_.confidence == "HIGH") + unused.count(_.confidence == "HIGH")
    println(s"\nTotal: $total findings ($high HIGH confidence)")
  }
}