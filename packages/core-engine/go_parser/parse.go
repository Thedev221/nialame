// Petit pont Go : lit du code Go sur stdin, extrait les informations
// utiles à l'analyse de sécurité (appels de fonction avec leur
// position, assignations) et les retourne en JSON sur stdout.
//
// Contrairement à esprima pour JS, l'AST natif Go (go/ast) n'est pas
// sérialisable en JSON directement — ce programme fait donc lui-même
// l'extraction plutôt que de retourner l'arbre complet. Invoqué en
// sous-processus depuis scanner_go.py — aucune autre responsabilité.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
)

type CallSite struct {
	QualifiedName string `json:"qualified_name"`
	StartLine     int    `json:"start_line"`
	StartColumn   int    `json:"start_column"`
	EndLine       int    `json:"end_line"`
	EndColumn     int    `json:"end_column"`
	Snippet       string `json:"snippet"`
	ArgsAreDynamic bool  `json:"args_are_dynamic"`
}

type ParseResult struct {
	CallSites []CallSite `json:"call_sites"`
	Error     string     `json:"error,omitempty"`
}

func qualifiedName(expr ast.Expr) string {
	switch fn := expr.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
	}
	return ""
}

// argsAreDynamic détecte une concaténation (+) parmi les arguments —
// motif équivalent à la détection de concaténation en Python/JS.
func argsAreDynamic(args []ast.Expr) bool {
	for _, arg := range args {
		if _, ok := arg.(*ast.BinaryExpr); ok {
			return true
		}
	}
	return false
}

func main() {
	src, err := io.ReadAll(os.Stdin)
	if err != nil {
		emitError(fmt.Sprintf("lecture stdin échouée : %v", err))
		return
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "input.go", src, parser.AllErrors)
	if err != nil {
		emitError(fmt.Sprintf("code Go invalide : %v", err))
		return
	}

	var callSites []CallSite

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := qualifiedName(call.Fun)
		if name == "" {
			return true
		}

		start := fset.Position(call.Pos())
		end := fset.Position(call.End())

		callSites = append(callSites, CallSite{
			QualifiedName:  name,
			StartLine:      start.Line,
			StartColumn:    start.Column - 1,
			EndLine:        end.Line,
			EndColumn:      end.Column - 1,
			ArgsAreDynamic: argsAreDynamic(call.Args),
		})
		return true
	})

	result := ParseResult{CallSites: callSites}
	output, _ := json.Marshal(result)
	fmt.Println(string(output))
}

func emitError(message string) {
	result := ParseResult{Error: message}
	output, _ := json.Marshal(result)
	fmt.Fprintln(os.Stderr, string(output))
	os.Exit(1)
}
