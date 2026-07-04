package detector

import (
	"regexp"
	"strings"
)

// SQLSemantic est le moteur d'analyse sémantique des injections SQL.
//
// Principe (comme libinjection) : au lieu de chercher des chaînes ("UNION
// SELECT") avec des regex, on TOKENISE l'entrée comme le ferait un analyseur
// SQL, puis on raisonne sur la STRUCTURE de la suite de tokens. On voit ainsi
// à travers l'obfuscation (UN/**/ION, casse, espaces) tout en générant peu de
// faux positifs (une phrase contenant "select" ou "or" ne forme aucune
// structure d'injection).
type SQLSemantic struct{}

func (SQLSemantic) Name() string { return "semantic-sql" }

var (
	sqlKeywords = set(
		"select", "union", "insert", "update", "delete", "drop", "create",
		"alter", "from", "where", "and", "or", "not", "having", "group", "by",
		"order", "into", "values", "table", "database", "exec", "execute",
		"declare", "cast", "convert", "like", "between", "all", "any", "as",
		"join", "on", "limit", "offset", "waitfor", "delay", "xor", "is", "null",
	)
	sqlFunctions = set(
		"sleep", "benchmark", "pg_sleep", "concat", "concat_ws",
		"group_concat", "substring", "substr", "ascii", "char", "load_file",
		"updatexml", "extractvalue", "version", "user", "database",
		"current_user", "md5", "hex", "unhex", "if", "ifnull", "count",
		"floor", "rand", "dbms_pipe",
	)
	stmtKeywords = set(
		"select", "insert", "update", "delete", "drop", "create", "alter",
		"exec", "execute", "declare", "grant", "truncate",
	)
	compareOps  = set("=", "<", ">", "<=", ">=", "<>", "!=", "<=>")
	blockComRe  = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

// token : Typ ∈ {k,f,1,n,s,v,o,(,),comma,semicolon,c}
type token struct {
	Typ string
	Lex string
}

type signals struct {
	inlineComment bool
	unterminated  bool
	lineComment   bool
}

func stripBlockComments(text string) (string, bool) {
	inline := blockComRe.MatchString(text)
	// en SQL réel /**/ agit comme un séparateur : on remplace par une espace
	cleaned := blockComRe.ReplaceAllString(text, " ")
	return cleaned, inline
}

func tokenize(text string) ([]token, signals) {
	text, inline := stripBlockComments(text)
	sig := signals{inlineComment: inline}
	var toks []token
	r := []rune(text)
	n := len(r)
	i := 0

	isWordStart := func(c rune) bool { return c == '_' || isAlpha(c) }
	isWord := func(c rune) bool { return c == '_' || isAlpha(c) || isDigit(c) }

	for i < n {
		c := r[i]

		if isSpace(c) {
			i++
			continue
		}

		// commentaires de ligne  -- ...  ou  # ...
		if (c == '-' && i+1 < n && r[i+1] == '-') || c == '#' {
			sig.lineComment = true
			toks = append(toks, token{"c", "--"})
			for i < n && r[i] != '\n' {
				i++
			}
			continue
		}

		// chaînes '...' ou "..."
		if c == '\'' || c == '"' {
			quote := c
			j := i + 1
			closed := false
			for j < n {
				if r[j] == '\\' {
					j += 2
					continue
				}
				if r[j] == quote {
					closed = true
					j++
					break
				}
				j++
			}
			if !closed {
				sig.unterminated = true
			}
			toks = append(toks, token{"s", strings.ToLower(string(r[i:min(j, n)]))})
			i = j
			continue
		}

		// variables @x / @@version
		if c == '@' {
			j := i + 1
			if j < n && r[j] == '@' {
				j++
			}
			for j < n && isWord(r[j]) {
				j++
			}
			toks = append(toks, token{"v", strings.ToLower(string(r[i:j]))})
			i = j
			continue
		}

		// nombres (dont hex 0x..)
		if isDigit(c) {
			j := i
			if c == '0' && i+1 < n && (r[i+1] == 'x' || r[i+1] == 'X') {
				j = i + 2
				for j < n && isHex(r[j]) {
					j++
				}
			} else {
				for j < n && (isDigit(r[j]) || r[j] == '.') {
					j++
				}
			}
			toks = append(toks, token{"n", strings.ToLower(string(r[i:j]))})
			i = j
			continue
		}

		// mots : mot-clé / fonction / identifiant
		if isWordStart(c) {
			j := i
			for j < n && isWord(r[j]) {
				j++
			}
			word := strings.ToLower(string(r[i:j]))
			switch {
			case sqlKeywords[word]:
				toks = append(toks, token{"k", word})
			case sqlFunctions[word]:
				toks = append(toks, token{"f", word})
			default:
				toks = append(toks, token{"1", word})
			}
			i = j
			continue
		}

		// ponctuation structurante
		switch c {
		case '(':
			toks = append(toks, token{"(", "("})
			i++
			continue
		case ')':
			toks = append(toks, token{")", ")"})
			i++
			continue
		case ',':
			toks = append(toks, token{"comma", ","})
			i++
			continue
		case ';':
			toks = append(toks, token{"semicolon", ";"})
			i++
			continue
		}

		// opérateurs (multi-caractères d'abord)
		if i+1 < n {
			two := string(r[i : i+2])
			switch two {
			case "<=", ">=", "<>", "!=", "||", "&&", ":=":
				toks = append(toks, token{"o", two})
				i += 2
				continue
			}
		}
		if strings.ContainsRune("=<>!+-*/%|&^~", c) {
			toks = append(toks, token{"o", string(c)})
			i++
			continue
		}

		i++ // caractère ignoré
	}
	return toks, sig
}

// analyzeOnce applique les signatures structurelles à UN contexte.
func analyzeOnce(text string) []Finding {
	toks, sig := tokenize(text)
	var out []Finding
	add := func(id, name string, sev int) {
		out = append(out, Finding{ID: id, Category: "sqli", Name: name,
			Severity: sev, Engine: "semantic"})
	}
	lit := func(t string) bool { return t == "n" || t == "s" }

	// 1) UNION [ALL] SELECT
	for idx, t := range toks {
		if t.Typ == "k" && t.Lex == "union" {
			for k := idx + 1; k < idx+3 && k < len(toks); k++ {
				if toks[k].Lex == "select" {
					add("SEM-SQL-UNION", "Requête UNION SELECT (extraction de données)", 6)
					break
				}
			}
		}
	}

	// 2) Requête empilée : ; suivi d'un mot-clé d'instruction
	for idx, t := range toks {
		if t.Typ == "semicolon" && idx+1 < len(toks) {
			nx := toks[idx+1]
			if nx.Typ == "k" && stmtKeywords[nx.Lex] {
				add("SEM-SQL-STACK", "Requête empilée après ';' (stacked query)", 6)
				break
			}
		}
	}

	// 3) Tautologie : OR/AND + comparaison de littéraux, ou littéral nu
	for idx, t := range toks {
		if t.Typ == "k" && (t.Lex == "or" || t.Lex == "and" || t.Lex == "xor") {
			w := toks[idx+1 : min(idx+4, len(toks))]
			if len(w) >= 3 && lit(w[0].Typ) && w[1].Typ == "o" &&
				compareOps[w[1].Lex] && lit(w[2].Typ) {
				add("SEM-SQL-TAUTO", "Condition toujours vraie (tautologie OR/AND)", 5)
				break
			}
			if len(w) >= 1 && lit(w[0].Typ) &&
				(len(w) == 1 || w[1].Typ == ")" || w[1].Typ == "c" || w[1].Typ == "semicolon") {
				add("SEM-SQL-TAUTO", "Condition vraie par littéral (OR 1 / OR 'x')", 5)
				break
			}
		}
	}

	// 3bis) Comparaison de littéraux identiques : 1=1
	for idx := 0; idx+2 < len(toks); idx++ {
		a, op, b := toks[idx], toks[idx+1], toks[idx+2]
		if lit(a.Typ) && op.Typ == "o" && compareOps[op.Lex] && lit(b.Typ) && a.Lex == b.Lex {
			add("SEM-SQL-TAUTO", "Comparaison tautologique de littéraux", 4)
			break
		}
	}

	// 4) Fonctions temporelles / blind
	for _, t := range toks {
		if t.Typ == "f" && (t.Lex == "sleep" || t.Lex == "benchmark" || t.Lex == "pg_sleep") {
			add("SEM-SQL-TIME", "Fonction temporelle "+t.Lex+"() (injection à l'aveugle)", 5)
			break
		}
		if t.Typ == "k" && t.Lex == "waitfor" {
			add("SEM-SQL-TIME", "WAITFOR DELAY (injection temporelle)", 5)
			break
		}
	}

	// 5) Échappement de chaîne : chaîne non terminée + structure SQL
	if sig.unterminated {
		hasSQL := false
		for _, t := range toks {
			if t.Typ == "k" || (t.Typ == "o" && compareOps[t.Lex]) {
				hasSQL = true
				break
			}
		}
		if hasSQL {
			add("SEM-SQL-BREAK", "Sortie de contexte chaîne ('...) vers du SQL", 4)
		}
	}

	// 5bis) Chaîne fermée immédiatement suivie d'un commentaire : admin'--
	for idx := 0; idx+1 < len(toks); idx++ {
		if toks[idx].Typ == "s" && toks[idx+1].Typ == "c" {
			add("SEM-SQL-AUTHBYPASS", "Chaîne fermée + commentaire (contournement d'auth)", 5)
			break
		}
	}

	// 6) Évasion par commentaire inline dans un contexte SQL
	if sig.inlineComment {
		for _, t := range toks {
			if t.Typ == "k" || t.Typ == "f" {
				add("SEM-SQL-EVASION", "Commentaire inline /**/ d'évasion", 3)
				break
			}
		}
	}

	// 7) Commentaire terminant une requête après du SQL
	if sig.lineComment {
		hasAuth := false
		hasSQL := false
		for _, f := range out {
			if f.ID == "SEM-SQL-AUTHBYPASS" {
				hasAuth = true
			}
		}
		for _, t := range toks {
			if t.Typ == "k" || t.Typ == "f" || t.Typ == "o" {
				hasSQL = true
				break
			}
		}
		if hasSQL && !hasAuth {
			add("SEM-SQL-COMMENT", "Commentaire neutralisant la fin de requête", 3)
		}
	}

	// dédoublonnage par signature (score max)
	uniq := map[string]Finding{}
	for _, f := range out {
		if e, ok := uniq[f.ID]; !ok || f.Severity > e.Severity {
			uniq[f.ID] = f
		}
	}
	res := make([]Finding, 0, len(uniq))
	for _, f := range uniq {
		res = append(res, f)
	}
	return res
}

// scanSQL fait l'analyse multi-contexte (comme libinjection) d'UNE valeur et
// renvoie l'interprétation la plus suspecte : telle quelle, ou comme si
// l'entrée était déjà à l'intérieur d'une chaîne '...' ou "...".
func scanSQL(value string) []Finding {
	if value == "" {
		return nil
	}
	var best []Finding
	bestScore := 0
	for _, prefix := range []string{"", "'", "\""} {
		f := analyzeOnce(prefix + value)
		s := 0
		for _, x := range f {
			s += x.Severity
		}
		if s > bestScore {
			bestScore = s
			best = f
		}
	}
	return best
}

// Inspect applique l'analyse SQL à toutes les valeurs de la requête.
func (SQLSemantic) Inspect(req Request) []Finding {
	var out []Finding
	for _, v := range req.Values {
		out = append(out, scanSQL(v)...)
	}
	return out
}

// ---- petites aides (évitent toute dépendance externe) ----
func isSpace(c rune) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' }
func isDigit(c rune) bool { return c >= '0' && c <= '9' }
func isAlpha(c rune) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isHex(c rune) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
