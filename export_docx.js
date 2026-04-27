#!/usr/bin/env node
/**
 * HUNTER Word export pipeline.
 * Supports both the legacy plan format and the v2 hunt-pack report format.
 */

const path = require('path');
const Module = require('module');
const SCRIPT_DIR = path.dirname(path.resolve(__filename));
Module.globalPaths.unshift(path.join(SCRIPT_DIR, 'node_modules'));
const JSZip = require('jszip');

const {
  Document,
  Packer,
  Paragraph,
  TextRun,
  Table,
  TableRow,
  TableCell,
  Header,
  Footer,
  HeadingLevel,
  AlignmentType,
  BorderStyle,
  WidthType,
  ShadingType,
  VerticalAlign,
  LevelFormat,
  PageBreak,
  SimpleField,
} = require('docx');

const fs = require('fs');

const planPath = process.argv[2];
const outPath = process.argv[3] || 'hunt_plan.docx';
if (!planPath) {
  console.error('Usage: node export_docx.js <plan.json> [output.docx]');
  process.exit(1);
}

const plan = JSON.parse(fs.readFileSync(planPath, 'utf8'));
const isHuntPackV2 =
  plan.document_type === 'hunt_pack_v2' ||
  (plan.payload && Array.isArray(plan.payload.steps));

const C = {
  navy: '0A2744',
  accent: '0077A8',
  red: 'C1121F',
  white: 'FFFFFF',
  muted: '6B7280',
  border: 'D1D5DB',
  rowHdr: '0A3D5F',
  rowAlt: 'EBF8FD',
  success: '1E6B45',
  amber: 'B45309',
  slate: 'F8FAFC',
  soft: 'F3F4F6',
};

const B_SINGLE = (color = C.border, size = 4) => ({
  style: BorderStyle.SINGLE,
  size,
  color,
});

const BORDERS_ALL = (color = C.border, size = 4) => ({
  top: B_SINGLE(color, size),
  bottom: B_SINGLE(color, size),
  left: B_SINGLE(color, size),
  right: B_SINGLE(color, size),
});

const CM = { top: 80, bottom: 80, left: 120, right: 120 };
const CM_SM = { top: 60, bottom: 60, left: 100, right: 100 };

function run(text, opts = {}) {
  return new TextRun({
    text: String(text ?? ''),
    font: opts.font || 'Arial',
    size: opts.size || 20,
    bold: !!opts.bold,
    color: opts.color || '111111',
    italics: !!opts.italic,
  });
}

function para(children, opts = {}) {
  const cfg = {
    spacing: { before: opts.before ?? 40, after: opts.after ?? 40 },
    alignment: opts.align || AlignmentType.LEFT,
    children: Array.isArray(children) ? children : [children],
  };
  if (opts.heading) cfg.heading = opts.heading;
  if (opts.numbering) cfg.numbering = opts.numbering;
  if (opts.indent) cfg.indent = opts.indent;
  if (opts.border) cfg.border = opts.border;
  return new Paragraph(cfg);
}

function spacer(n = 80) {
  return para([run('')], { before: 0, after: n });
}

function divider(color = C.accent) {
  return para([run('')], {
    before: 0,
    after: 0,
    border: {
      bottom: { style: BorderStyle.SINGLE, size: 6, color, space: 1 },
    },
  });
}

function cell(paragraphs, opts = {}) {
  const cfg = {
    width: { size: opts.width ?? 4680, type: WidthType.DXA },
    margins: opts.margins ?? CM,
    verticalAlign: opts.vAlign ?? VerticalAlign.TOP,
    children: Array.isArray(paragraphs) ? paragraphs : [paragraphs],
  };
  if (opts.borders !== undefined) cfg.borders = opts.borders;
  if (opts.shading) cfg.shading = { fill: opts.shading, type: ShadingType.CLEAR };
  return new TableCell(cfg);
}

function hCell(text, width, bg = C.rowHdr) {
  return cell(
    [para([run(text, { bold: true, color: C.white, size: 18 })], { before: 0, after: 0 })],
    { width, shading: bg, borders: BORDERS_ALL(C.border), margins: CM_SM }
  );
}

function dCell(text, width, shade) {
  return cell(
    [para([run(text, { size: 18 })], { before: 0, after: 0 })],
    { width, shading: shade || null, borders: BORDERS_ALL(C.border), margins: CM_SM }
  );
}

function bullet(text, opts = {}) {
  return para(
    [run(text, { size: opts.size || 18, color: opts.color || '111111', italic: !!opts.italic })],
    {
      before: opts.before ?? 0,
      after: opts.after ?? 20,
      numbering: { reference: 'bullets', level: 0 },
    }
  );
}

function codeBlock(text) {
  const lines = String(text || '').split(/\r?\n/);
  const paragraphs = lines.length
    ? lines.map(line =>
        para(
          [run(line || ' ', { font: 'Courier New', size: 17, color: C.navy })],
          { before: 0, after: 10 }
        )
      )
    : [
        para(
          [run('No rendered query or workflow was captured for this step.', { size: 18, color: C.muted, italic: true })],
          { before: 0, after: 0 }
        ),
      ];

  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [9360],
    rows: [
      new TableRow({
        children: [
          cell(paragraphs, {
            width: 9360,
            shading: C.slate,
            borders: BORDERS_ALL(C.border),
            margins: { top: 120, bottom: 120, left: 140, right: 140 },
          }),
        ],
      }),
    ],
  });
}

function pageBreak() {
  return para([new PageBreak()], { before: 0, after: 0 });
}

function toDisplayDate(value) {
  if (!value) {
    return new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  }
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  }
  return String(value);
}

function listText(values, fallback = 'None') {
  if (!Array.isArray(values) || !values.length) return fallback;
  return values.join(', ');
}

function shortText(value, limit = 180) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (!text) return 'Not recorded';
  if (text.length <= limit) return text;
  return `${text.slice(0, Math.max(0, limit - 1)).trim()}...`;
}

function threatContext() {
  if (Array.isArray(plan.threat_context) && plan.threat_context.length) {
    return plan.threat_context;
  }
  const summary = huntSummary();
  return (summary.selected_threats || []).map(name => ({
    name,
    summary: '',
    aliases: [],
    techniques: [],
    indicators: [],
    indicator_count: 0,
    extra_hunts: [],
    references: [],
    tags: [],
  }));
}

function metaRow(label, value, shade) {
  return new TableRow({
    children: [
      hCell(label, 2200),
      dCell(value, 7160, shade),
    ],
  });
}

function huntSummary() {
  return plan.summary || {};
}

function huntPayload() {
  return plan.payload || {};
}

function huntSteps() {
  const payload = huntPayload();
  return Array.isArray(payload.steps) ? payload.steps : [];
}

function buildHeader() {
  const title = isHuntPackV2 ? 'THREAT HUNT REPORT' : 'THREAT HUNT PLAN';
  return new Header({
    children: [
      para(
        [
          run('H  HUNTER', { bold: true, size: 18, color: C.red }),
          run(`   -   ${title}`, { size: 16, color: C.muted }),
          run('          SENSITIVE // HUNT OPERATIONS', { size: 14, color: C.muted }),
        ],
        {
          before: 0,
          after: 80,
          border: {
            bottom: { style: BorderStyle.SINGLE, size: 4, color: C.accent, space: 1 },
          },
        }
      ),
    ],
  });
}

function buildFooter() {
  return new Footer({
    children: [
      para(
        [
          run(`HUNTER  |  ${new Date().toLocaleDateString()}  |  Page `, {
            size: 16,
            color: C.muted,
          }),
          new SimpleField('PAGE'),
        ],
        {
          before: 60,
          after: 0,
          border: {
            top: { style: BorderStyle.SINGLE, size: 2, color: C.border, space: 1 },
          },
        }
      ),
    ],
  });
}

function buildHuntPackCover() {
  const summary = huntSummary();
  const steps = huntSteps();
  const threats = threatContext();
  return [
    spacer(1200),
    para(
      [
        run('H', { bold: true, size: 120, color: C.red }),
        run('  HUNTER', { bold: true, size: 80, color: C.navy }),
      ],
      { align: AlignmentType.CENTER, before: 0, after: 60 }
    ),
    para([run('THREAT HUNT REPORT', { bold: true, size: 40, color: C.accent })], {
      align: AlignmentType.CENTER,
      before: 0,
      after: 40,
    }),
    divider(C.accent),
    spacer(220),
    para(
      [run(plan.name || summary.mission_name || 'Generated Hunt Pack', { bold: true, size: 34, color: C.navy })],
      { align: AlignmentType.CENTER, before: 0, after: 60 }
    ),
    para([run(`Generated: ${toDisplayDate(summary.generated_at || plan.updated_at || plan.created_at)}`, { size: 22, color: C.muted })], {
      align: AlignmentType.CENTER,
      before: 0,
      after: 40,
    }),
    para(
      [
        run(
          `Threats: ${threats.length}  ·  Tools: ${(summary.selected_tools || []).length}  ·  Steps: ${steps.length}`,
          { bold: true, size: 22, color: C.navy }
        ),
      ],
      { align: AlignmentType.CENTER, before: 0, after: 20 }
    ),
    para(
      [
        run(
          `ATT&CK Covered: ${(summary.covered_techniques || []).length}  ·  Gaps: ${(summary.missing_techniques || []).length}`,
          { size: 20, color: C.accent }
        ),
      ],
      { align: AlignmentType.CENTER, before: 0, after: 220 }
    ),
    para([run('SENSITIVE  //  HUNT OPERATIONS', { bold: true, size: 18, color: C.red })], {
      align: AlignmentType.CENTER,
    }),
    pageBreak(),
  ];
}

function buildHuntPackSummary() {
  const summary = huntSummary();
  const steps = huntSteps();
  const threats = threatContext();

  const statsTable = new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [2340, 2340, 2340, 2340],
    rows: [
      new TableRow({
        children: [
          hCell('Steps', 2340),
          hCell('Threats', 2340),
          hCell('Tools', 2340),
          hCell('Coverage', 2340),
        ],
      }),
      new TableRow({
        children: [
          dCell(String(steps.length), 2340, C.rowAlt),
          dCell(String(threats.length), 2340),
          dCell(String((summary.selected_tools || []).length), 2340, C.rowAlt),
          dCell(`${(summary.covered_techniques || []).length} covered / ${(summary.missing_techniques || []).length} gaps`, 2340),
        ],
      }),
    ],
  });

  const summaryTable = new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [2200, 7160],
    rows: [
      metaRow('Mission', summary.mission_name || plan.name || 'Generated Hunt Pack', C.rowAlt),
      metaRow('Generated', toDisplayDate(summary.generated_at || plan.updated_at || plan.created_at), undefined),
      metaRow('Threat Scope', threats.length ? `${threats.length} selected threat${threats.length === 1 ? '' : 's'}` : 'None', C.rowAlt),
      metaRow('Tool Selection', listText(summary.selected_tools), undefined),
      metaRow('Manual ATT&CK', listText(summary.selected_manual_mitre), C.rowAlt),
      metaRow('Authored Hunts', String(((summary.content_origin_counts || {}).authored_tool_hunt) || 0), undefined),
      metaRow('Sigma Steps', String(((summary.content_origin_counts || {}).sigma_translated) || 0), C.rowAlt),
      metaRow('ATT&CK Covered', listText(summary.covered_techniques), C.rowAlt),
      metaRow('Coverage Gaps', listText(summary.missing_techniques), undefined),
    ],
  });

  return [
    para([run('Executive Summary', { bold: true, size: 32, color: C.navy })], {
      heading: HeadingLevel.HEADING_1,
    }),
    divider(),
    spacer(60),
    para(
      [
        run(
          `This report captures the generated hunt pack for ${summary.mission_name || plan.name || 'the current mission'}. ` +
            `It summarizes the selected threat modules, the tool coverage brought into scope, and the ranked hunt steps the analyst should execute.`,
          { size: 20 }
        ),
      ],
      { before: 0, after: 120 }
    ),
    statsTable,
    spacer(90),
    summaryTable,
    spacer(90),
    para([run('Coverage Notes', { bold: true, size: 22, color: C.navy })], {
      before: 80,
      after: 30,
    }),
    bullet(
      (summary.covered_techniques || []).length
        ? `The current selection covers ${summary.covered_techniques.length} ATT&CK techniques across the chosen tools.`
        : 'No ATT&CK coverage was recorded in the current draft.'
    ),
    bullet(
      (summary.missing_techniques || []).length
        ? `Remaining ATT&CK gaps still require analyst review: ${listText(summary.missing_techniques)}.`
        : 'No ATT&CK gaps remain for the selected threat-to-tool combination.'
    ),
    spacer(90),
  ];
}

function buildThreatScope() {
  const threats = threatContext();
  if (!threats.length) return [];

  const rows = [
    new TableRow({
      children: [
        hCell('Threat', 1800),
        hCell('Summary', 3860),
        hCell('ATT&CK', 1150),
        hCell('IOCs', 1050),
        hCell('Aliases', 1500),
      ],
    }),
  ];

  threats.forEach((threat, index) => {
    const techniques = Array.isArray(threat.techniques) ? threat.techniques : [];
    const aliases = Array.isArray(threat.aliases) ? threat.aliases : [];
    const indicators = Array.isArray(threat.indicators) ? threat.indicators : [];
    const indicatorCount = Number.isFinite(Number(threat.indicator_count))
      ? Number(threat.indicator_count)
      : indicators.length;
    const shade = index % 2 === 0 ? C.rowAlt : undefined;
    rows.push(
      new TableRow({
        children: [
          dCell(threat.name || threat.external_id || 'Unnamed threat', 1800, shade),
          dCell(shortText(threat.summary, 220), 3860, shade),
          dCell(String(techniques.length), 1150, shade),
          dCell(String(indicatorCount), 1050, shade),
          dCell(String(aliases.length), 1500, shade),
        ],
      })
    );
  });

  const out = [
    para([run('Threat Scope', { bold: true, size: 30, color: C.navy })], {
      heading: HeadingLevel.HEADING_1,
      before: 120,
      after: 30,
    }),
    divider(),
    spacer(50),
    para(
      [
        run(
          'Threat details are summarized for quick scanning. Expand each Additional Details heading for full aliases, indicators, references, tags, and extra hunt notes.',
          { size: 18, color: C.muted }
        ),
      ],
      { before: 0, after: 80 }
    ),
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [1800, 3860, 1150, 1050, 1500],
      rows,
    }),
    spacer(80),
  ];

  threats.forEach(threat => {
    const threatName = threat.name || threat.external_id || 'Threat';
    out.push(
      para([run(`Additional Details: ${threatName}`, { bold: true, size: 22, color: C.accent })], {
        heading: HeadingLevel.HEADING_3,
        before: 90,
        after: 20,
      })
    );
    out.push(
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [2200, 7160],
        rows: [
          metaRow('External ID', threat.external_id || 'N/A', C.rowAlt),
          metaRow('Aliases', listText(threat.aliases), undefined),
          metaRow('Techniques', listText(threat.techniques), C.rowAlt),
          metaRow('Tags', listText(threat.tags), undefined),
        ],
      })
    );

    const indicators = Array.isArray(threat.indicators) ? threat.indicators : [];
    out.push(para([run('Indicators', { bold: true, size: 18, color: C.navy })], { before: 30, after: 10 }));
    if (indicators.length) {
      indicators.forEach(indicator => out.push(bullet(`${indicator.type || 'indicator'}: ${indicator.value || ''}`)));
    } else {
      out.push(para([run('No indicators were recorded for this threat.', { size: 18, color: C.muted, italic: true })], { before: 0, after: 20 }));
    }

    const extraHunts = Array.isArray(threat.extra_hunts) ? threat.extra_hunts : [];
    out.push(para([run('Extra Hunt Notes', { bold: true, size: 18, color: C.navy })], { before: 30, after: 10 }));
    if (extraHunts.length) {
      extraHunts.forEach(item => out.push(bullet(item)));
    } else {
      out.push(para([run('No extra hunt notes were recorded for this threat.', { size: 18, color: C.muted, italic: true })], { before: 0, after: 20 }));
    }

    const references = Array.isArray(threat.references) ? threat.references : [];
    out.push(para([run('References', { bold: true, size: 18, color: C.navy })], { before: 30, after: 10 }));
    if (references.length) {
      references.forEach(item => out.push(bullet(item)));
    } else {
      out.push(para([run('No references were recorded for this threat.', { size: 18, color: C.muted, italic: true })], { before: 0, after: 20 }));
    }
    out.push(spacer(40));
  });

  return out;
}

function buildHuntPackStep(step, index) {
  const iocInsertions = Object.entries(step.ioc_insertions || {}).map(([key, value]) => `${key} => ${value}`);
  const unresolved = step.unresolved_placeholders || [];
  const out = [
    para(
      [
        run(`Step ${String(index).padStart(2, '0')}  `, { bold: true, size: 20, color: C.accent }),
        run(step.title || 'Untitled Hunt Step', { bold: true, size: 28, color: C.navy }),
      ],
      {
        heading: HeadingLevel.HEADING_2,
        before: 140,
        after: 20,
      }
    ),
    divider(unresolved.length ? C.amber : C.accent),
    spacer(40),
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [2200, 7160],
      rows: [
        metaRow('Tool', step.tool_pack || 'Unknown', C.rowAlt),
        metaRow('Content Origin', (step.content_origin || 'authored_tool_hunt').replace(/_/g, ' '), undefined),
        metaRow('Sigma Rule', step.sigma_rule_id ? `${step.sigma_title || 'Sigma Rule'} (${step.sigma_rule_id})` : 'N/A', C.rowAlt),
        metaRow('Translation Target', step.translation_target || 'N/A', undefined),
        metaRow('Method Strength', (step.method_strength || 'primary_hunt').replace(/_/g, ' '), undefined),
        metaRow('Method Kind', (step.method_kind || 'behavior_hunt').replace(/_/g, ' '), C.rowAlt),
        metaRow('Execution Surface', step.execution_surface || 'Not recorded', undefined),
        metaRow('Surface Details', step.surface_details || 'Not recorded', C.rowAlt),
        metaRow('Techniques', listText(step.techniques), undefined),
        metaRow('Safety Labels', listText(step.safety_labels), C.rowAlt),
        metaRow('Noise / Privilege', `${step.noise_level || 'unknown'} / ${step.privilege_required || 'unknown'}`, undefined),
        metaRow('Data Sources', listText(step.data_sources), C.rowAlt),
      ],
    }),
    spacer(50),
    para([run('Expectation', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }),
    para([run(step.expectation || 'Review resulting hits for behavior aligned to the mapped ATT&CK techniques.', { size: 18 })], {
      before: 0,
      after: 50,
    }),
    para([run('Behavior Focus', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }),
    para([run(step.behavior_focus || 'No authored behavior focus was recorded for this step.', { size: 18 })], {
      before: 0,
      after: 50,
    }),
    para([run('Method Strength Rationale', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }),
    para([run(step.strength_reason || 'No authored strength rationale was recorded for this step.', { size: 18 })], {
      before: 0,
      after: 50,
    }),
    para([run('Why This Step Was Selected', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }),
    para([run(step.why_selected || 'Generated from the selected threat and tool combination.', { size: 18 })], {
      before: 0,
      after: 50,
    }),
    para([run('Prerequisites', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }),
  ];

  if ((step.prerequisites || []).length) {
    step.prerequisites.forEach(item => out.push(bullet(item)));
  } else {
    out.push(
      para([run('No explicit prerequisites were recorded for this step.', { size: 18, color: C.muted, italic: true })], {
        before: 0,
        after: 40,
      })
    );
  }

  out.push(para([run('IOC Insertions', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }));
  if (iocInsertions.length) {
    iocInsertions.forEach(item => out.push(bullet(item)));
  } else {
    out.push(
      para([run('No IOC values were inserted for this step.', { size: 18, color: C.muted, italic: true })], {
        before: 0,
        after: 40,
      })
    );
  }

  out.push(para([run('Unresolved Placeholders', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }));
  out.push(
    para(
      [
        run(unresolved.length ? listText(unresolved) : 'None remaining.', {
          size: 18,
          color: unresolved.length ? C.amber : C.success,
        }),
      ],
      { before: 0, after: 50 }
    )
  );

  out.push(para([run('Surface Examples', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }));
  if ((step.service_examples || []).length) {
    step.service_examples.forEach(item => out.push(bullet(item)));
  } else {
    out.push(
      para([run('No explicit service examples were recorded for this step.', { size: 18, color: C.muted, italic: true })], {
        before: 0,
        after: 40,
      })
    );
  }

  out.push(para([run('Rendered Query / Workflow', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }));
  out.push(codeBlock(step.rendered_query || ''));
  if (step.raw_rule_url) {
    out.push(para([run('Sigma Source', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }));
    out.push(
      para([run(step.raw_rule_url, { size: 18, color: C.accent })], {
        before: 0,
        after: 40,
      })
    );
  }
  out.push(spacer(90));
  return out;
}

function buildHuntPackChildren() {
  const children = [
    ...buildHuntPackCover(),
    ...buildHuntPackSummary(),
    ...buildThreatScope(),
  ];
  huntSteps().forEach((step, index) => {
    children.push(...buildHuntPackStep(step, index + 1));
  });
  return children;
}

function legacyModules() {
  return Array.isArray(plan.modules) ? plan.modules : [];
}

function legacyQuestions() {
  return legacyModules().flatMap(mod => (mod.questions || []).map(question => ({ module: mod.name, question })));
}

function buildLegacyCover() {
  const modules = legacyModules();
  const questionCount = legacyQuestions().length;
  const huntActions = modules.reduce((total, mod) => {
    return total + (mod.hunt_actions || []).reduce((count, group) => count + (group.actions || []).length, 0);
  }, 0);
  return [
    spacer(1200),
    para(
      [
        run('H', { bold: true, size: 120, color: C.red }),
        run('  HUNTER', { bold: true, size: 80, color: C.navy }),
      ],
      { align: AlignmentType.CENTER, before: 0, after: 60 }
    ),
    para([run('THREAT HUNT PLAN', { bold: true, size: 40, color: C.accent })], {
      align: AlignmentType.CENTER,
      before: 0,
      after: 40,
    }),
    divider(C.accent),
    spacer(200),
    para([run(`Generated: ${toDisplayDate()}`, { size: 22, color: C.muted })], {
      align: AlignmentType.CENTER,
    }),
    para(
      [run(`Modules: ${modules.length}  ·  Hunt Actions: ${huntActions}  ·  Questions: ${questionCount}`, { bold: true, size: 22, color: C.navy })],
      { align: AlignmentType.CENTER }
    ),
    spacer(300),
    para([run('SENSITIVE  //  HUNT OPERATIONS', { bold: true, size: 18, color: C.red })], {
      align: AlignmentType.CENTER,
    }),
    pageBreak(),
  ];
}

function buildLegacySummary() {
  const modules = legacyModules();
  const allMitre = [...new Set(modules.flatMap(mod => mod.mitre_techniques || []))];
  return [
    para([run('Executive Summary', { bold: true, size: 32, color: C.navy })], {
      heading: HeadingLevel.HEADING_1,
    }),
    divider(),
    spacer(60),
    para(
      [run(`This document presents a legacy HUNTER plan with ${modules.length} module(s) and ${allMitre.length} distinct ATT&CK technique references.`, { size: 20 })],
      { before: 0, after: 120 }
    ),
    para([run(`MITRE ATT&CK Coverage: ${listText(allMitre)}`, { size: 18 })], {
      before: 0,
      after: 60,
    }),
    spacer(60),
  ];
}

function buildLegacyModule(mod, index) {
  const out = [
    para(
      [
        run(`Module ${index + 1}  `, { bold: true, size: 20, color: C.accent }),
        run(mod.name || 'Untitled Module', { bold: true, size: 28, color: C.navy }),
      ],
      {
        heading: HeadingLevel.HEADING_2,
        before: 140,
        after: 20,
      }
    ),
    divider(),
    spacer(30),
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [2200, 7160],
      rows: [
        metaRow('Priority', mod.priority || 'High', C.rowAlt),
        metaRow('Estimated Hours', String(mod.estimated_hours || 0), undefined),
        metaRow('MITRE', listText(mod.mitre_techniques), C.rowAlt),
        metaRow('Tags', listText(mod.tags), undefined),
      ],
    }),
  ];

  if (mod.hunt_actions && mod.hunt_actions.length) {
    out.push(para([run('Hunt Actions', { bold: true, size: 20, color: C.navy })], { before: 30, after: 10 }));
    mod.hunt_actions.forEach(group => {
      out.push(para([run(group.title || 'Action Group', { bold: true, size: 18, color: C.accent })], { before: 20, after: 10 }));
      (group.actions || []).forEach(action => out.push(bullet(action)));
    });
  }

  out.push(spacer(70));
  return out;
}

function buildLegacyQuestionnaire() {
  const questions = legacyQuestions();
  if (!questions.length) return [];
  const out = [
    para([run('Pre-Hunt Questionnaire', { bold: true, size: 32, color: C.navy })], {
      heading: HeadingLevel.HEADING_1,
    }),
    divider(),
    spacer(60),
  ];
  questions.forEach((item, index) => {
    out.push(
      para([run(`Q${String(index + 1).padStart(2, '0')}  ${item.module}`, { bold: true, size: 18, color: C.navy })], {
        before: 30,
        after: 8,
      })
    );
    out.push(bullet(item.question));
    out.push(spacer(20));
  });
  return out;
}

function buildLegacyChildren() {
  return [
    ...buildLegacyCover(),
    ...buildLegacySummary(),
    ...legacyModules().flatMap((mod, index) => buildLegacyModule(mod, index)),
    ...buildLegacyQuestionnaire(),
  ];
}

async function addCollapsedThreatDetailMarkers(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const documentFile = zip.file('word/document.xml');
  if (!documentFile) return buffer;

  let xml = await documentFile.async('string');
  xml = xml.replace(/<w:p>[\s\S]*?<\/w:p>/g, paragraph => {
    if (!paragraph.includes('Additional Details:') || paragraph.includes('<w:collapsed/>')) {
      return paragraph;
    }
    if (paragraph.includes('<w:pPr>')) {
      return paragraph.replace('<w:pPr>', '<w:pPr><w:collapsed/>');
    }
    return paragraph.replace('<w:p>', '<w:p><w:pPr><w:collapsed/></w:pPr>');
  });

  zip.file('word/document.xml', xml);
  return zip.generateAsync({ type: 'nodebuffer' });
}

async function build() {
  const children = isHuntPackV2 ? buildHuntPackChildren() : buildLegacyChildren();

  const doc = new Document({
    numbering: {
      config: [
        {
          reference: 'bullets',
          levels: [
            {
              level: 0,
              format: LevelFormat.BULLET,
              text: '\u2022',
              alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: 720, hanging: 360 } } },
            },
          ],
        },
      ],
    },
    styles: {
      default: { document: { run: { font: 'Arial', size: 20 } } },
      paragraphStyles: [
        {
          id: 'Heading1',
          name: 'Heading 1',
          basedOn: 'Normal',
          next: 'Normal',
          quickFormat: true,
          run: { size: 32, bold: true, color: C.navy, font: 'Arial' },
          paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 0 },
        },
        {
          id: 'Heading2',
          name: 'Heading 2',
          basedOn: 'Normal',
          next: 'Normal',
          quickFormat: true,
          run: { size: 26, bold: true, color: C.accent, font: 'Arial' },
          paragraph: { spacing: { before: 180, after: 80 }, outlineLevel: 1 },
        },
        {
          id: 'Heading3',
          name: 'Heading 3',
          basedOn: 'Normal',
          next: 'Normal',
          quickFormat: true,
          run: { size: 22, bold: true, color: C.accent, font: 'Arial' },
          paragraph: { spacing: { before: 140, after: 60 }, outlineLevel: 2 },
        },
      ],
    },
    sections: [
      {
        properties: {
          page: {
            size: { width: 12240, height: 15840 },
            margin: { top: 1008, right: 1008, bottom: 1008, left: 1008 },
          },
        },
        headers: { default: buildHeader() },
        footers: { default: buildFooter() },
        children,
      },
    ],
  });

  const packed = await Packer.toBuffer(doc);
  const buffer = isHuntPackV2 ? await addCollapsedThreatDetailMarkers(packed) : packed;
  fs.writeFileSync(outPath, buffer);
  console.log(`Exported: ${outPath}  (${buffer.length} bytes)`);
}

build().catch(err => {
  console.error('Export failed:', err && err.stack ? err.stack : err);
  process.exit(1);
});
