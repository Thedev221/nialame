import { parseUnifiedDiff, extractChangedPythonFiles } from "../src/git/diffParser";

describe("parseUnifiedDiff", () => {
  it("extrait le chemin du fichier et ses lignes ajoutées", () => {
    const diff = [
      "diff --git a/app.py b/app.py",
      "index abc..def 100644",
      "--- a/app.py",
      "+++ b/app.py",
      "@@ -1,2 +1,3 @@",
      " def f():",
      "+    x = 1",
      "+    return x",
    ].join("\n");

    const result = parseUnifiedDiff(diff);

    expect(result).toHaveLength(1);
    expect(result[0].path).toBe("app.py");
    expect(result[0].addedLines).toEqual(["    x = 1", "    return x"]);
  });

  it("gère plusieurs fichiers dans un même diff", () => {
    const diff = [
      "+++ b/a.py",
      "+ligne a",
      "+++ b/b.py",
      "+ligne b",
    ].join("\n");

    const result = parseUnifiedDiff(diff);

    expect(result).toHaveLength(2);
    expect(result[0].path).toBe("a.py");
    expect(result[1].path).toBe("b.py");
  });

  it("ignore les lignes de contexte (non préfixées par +)", () => {
    const diff = ["+++ b/app.py", " ligne inchangée", "+ligne ajoutée"].join("\n");
    const result = parseUnifiedDiff(diff);

    expect(result[0].addedLines).toEqual(["ligne ajoutée"]);
  });

  it("ne confond pas l'en-tête +++ b/... avec une ligne ajoutée", () => {
    const diff = ["+++ b/app.py", "+vraie ligne ajoutée"].join("\n");
    const result = parseUnifiedDiff(diff);

    expect(result[0].addedLines).toEqual(["vraie ligne ajoutée"]);
    expect(result[0].addedLines).not.toContain("b/app.py");
  });

  it("gère un fichier supprimé (+++ /dev/null) sans planter", () => {
    const diff = ["--- a/deleted.py", "+++ /dev/null"].join("\n");
    const result = parseUnifiedDiff(diff);

    expect(result).toEqual([]);
  });

  it("retourne un tableau vide pour un diff vide", () => {
    expect(parseUnifiedDiff("")).toEqual([]);
  });
});

describe("extractChangedPythonFiles", () => {
  it("ne garde que les fichiers .py", () => {
    const diff = [
      "+++ b/app.py",
      "+x = 1",
      "+++ b/readme.md",
      "+# titre",
      "+++ b/script.js",
      "+console.log(1)",
    ].join("\n");

    expect(extractChangedPythonFiles(diff)).toEqual(["app.py"]);
  });

  it("retourne un tableau vide si aucun fichier Python modifié", () => {
    const diff = ["+++ b/readme.md", "+contenu"].join("\n");
    expect(extractChangedPythonFiles(diff)).toEqual([]);
  });
});
