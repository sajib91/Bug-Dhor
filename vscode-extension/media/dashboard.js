'use strict';

/**
 * Bug Dhor dashboard renderer.
 *
 * This file is loaded inside the dashboard webview. It renders the state sent
 * by the extension host and never invents analysis data, probabilities, SAE
 * activations, or causal effects. All dynamic text is written with textContent
 * or DOM properties; dynamic innerHTML is not used.
 */
(function dashboard() {
  const vscode = acquireVsCodeApi();

  const sectionIds = [
    'overview',
    'scan',
    'vulnerabilities',
    'saeFeatures',
    'featureInteractions',
    'securitySteering',
    'explanations',
    'automatedRepair',
    'verification',
    'researchReports',
    'settings'
  ];

  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const severityLabels = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low'
  };
  const severityTones = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low'
  };
  const badgeTones = new Set([
    'neutral',
    'critical',
    'high',
    'medium',
    'low',
    'success',
    'warning',
    'danger',
    'info'
  ]);
  const safeCommandPattern = /^bugdhor\.[A-Za-z][A-Za-z0-9]*$/;
  const demoFallbackNotice =
    'Demo data is shown for interface preview only. It was not produced by a scan or security ' +
    'engine, and no SAE, interaction, explanation, repair, or verification result is simulated.';
  const SVG_NAMESPACE = ['http', '://www.w3.org/2000/svg'].join('');

  const content = document.getElementById('dashboard-content');
  const bannerSlot = document.getElementById('dashboard-banner');
  const navList = document.getElementById('dashboard-tabs');
  const navButtons = navList ? Array.from(navList.querySelectorAll('.nav-item[data-section]')) : [];
  const dataModeBadge = document.getElementById('data-mode-badge');
  const lastUpdated = document.getElementById('last-updated');
  const refreshButton = document.getElementById('refresh-button');
  const demoButton = document.getElementById('demo-button');
  const logsButton = document.getElementById('logs-button');
  const enginePill = document.getElementById('engine-pill');
  const enginePillLabel = document.getElementById('engine-pill-label');

  const navSections = navButtons
    .map((button) => {
      const id = button.dataset.section;
      const labelNode = button.querySelector('.nav-label');
      const label = labelNode ? labelNode.textContent.trim() : id;
      return id ? { id, label } : null;
    })
    .filter(Boolean);

  let state = null;
  let activeSection = navSections[0] ? navSections[0].id : sectionIds[0];
  let transientNotice = null;
  let vulnerabilityFilter = { severity: 'all', cwe: 'all' };

  const restored = readRememberedState();
  if (restored && navSections.some((section) => section.id === restored.activeSection)) {
    activeSection = restored.activeSection;
  }

  bindChrome();
  bindMessageChannel();

  const initialRawState = readInitialState();
  if (initialRawState) {
    state = normalizeState(initialRawState);
    render();
  } else {
    renderBootError();
  }

  sendMessage({ type: 'ready' });

  // ---------------------------------------------------------------------
  // State and messaging
  // ---------------------------------------------------------------------

  function sendMessage(message) {
    try {
      vscode.postMessage(message);
    } catch (error) {
      console.error('Bug Dhor dashboard could not contact the extension host.', error);
      transientNotice = {
        level: 'error',
        message: 'The dashboard could not contact VS Code. See the Bug Dhor output channel.'
      };
      renderBanners();
    }
  }

  function bindMessageChannel() {
    window.addEventListener('message', (event) => {
      const message = event.data;
      if (!isRecord(message) || typeof message.type !== 'string') {
        return;
      }

      if (message.type === 'state') {
        state = normalizeState(message.state);
        if (
          vulnerabilityFilter.severity !== 'all' &&
          !severityOrder.includes(vulnerabilityFilter.severity)
        ) {
          vulnerabilityFilter.severity = 'all';
        }
        render();
        return;
      }

      if (message.type === 'notice') {
        const level =
          message.level === 'error' || message.level === 'warning' ? message.level : 'info';
        if (typeof message.message === 'string' && message.message.length > 0) {
          transientNotice = { level, message: message.message };
          renderBanners();
        }
      }
    });
  }

  function bindChrome() {
    if (refreshButton) {
      refreshButton.addEventListener('click', () => {
        sendMessage({ type: 'refresh' });
      });
    }

    if (demoButton) {
      demoButton.addEventListener('click', () => {
        const enabled = !state || state.dataMode !== 'demo';
        sendMessage({ type: 'setDemoMode', enabled });
      });
    }

    if (logsButton) {
      logsButton.addEventListener('click', () => {
        sendMessage({ type: 'showLogs' });
      });
    }

    if (!navList) {
      return;
    }

    navList.addEventListener('click', (event) => {
      const button = closestNavButton(event.target);
      if (button) {
        event.preventDefault();
        activateSection(button.dataset.section, false);
      }
    });

    navList.addEventListener('keydown', (event) => {
      const button = closestNavButton(event.target);
      if (!button) {
        return;
      }

      const currentIndex = navButtons.indexOf(button);
      let nextIndex;

      switch (event.key) {
        case 'ArrowDown':
        case 'ArrowRight':
          nextIndex = (currentIndex + 1) % navButtons.length;
          break;
        case 'ArrowUp':
        case 'ArrowLeft':
          nextIndex = (currentIndex - 1 + navButtons.length) % navButtons.length;
          break;
        case 'Home':
          nextIndex = 0;
          break;
        case 'End':
          nextIndex = navButtons.length - 1;
          break;
        default:
          return;
      }

      event.preventDefault();
      const nextButton = navButtons[nextIndex];
      activateSection(nextButton.dataset.section, true);
    });
  }

  function closestNavButton(target) {
    if (!(target instanceof Element)) {
      return null;
    }
    const button = target.closest('.nav-item[data-section]');
    return button && navButtons.includes(button) ? button : null;
  }

  function activateSection(sectionId, moveFocus) {
    if (typeof sectionId !== 'string' || !navSections.some((item) => item.id === sectionId)) {
      return;
    }

    activeSection = sectionId;
    updateNavigation();

    const activeButton = navButtons.find((button) => button.dataset.section === sectionId);
    if (moveFocus && activeButton) {
      activeButton.focus();
    }

    renderActiveSection();
    rememberState({ activeSection });
  }

  function rememberState(value) {
    try {
      vscode.setState(value);
    } catch (error) {
      console.error('Bug Dhor dashboard could not persist its view state.', error);
    }
  }

  function readRememberedState() {
    try {
      const value = vscode.getState();
      return isRecord(value) ? value : null;
    } catch (error) {
      console.error('Bug Dhor dashboard could not restore its view state.', error);
      return null;
    }
  }

  function readInitialState() {
    const node = document.getElementById('dashboard-state');
    if (!node) {
      return null;
    }
    try {
      return JSON.parse(node.textContent || '{}');
    } catch (error) {
      console.error('Bug Dhor dashboard state could not be parsed.', error);
      return null;
    }
  }

  function normalizeFeedback(raw) {
    const source = isRecord(raw) ? raw : {};
    const stats = isRecord(source.stats) ? source.stats : {};
    return {
      findings: arrayOfRecords(source.findings),
      patchHistory: arrayOfRecords(source.patchHistory),
      stats: {
        scans: numberOrNull(stats.scans),
        suppressed: numberOrNull(stats.suppressed),
        followUpRescans: numberOrNull(stats.followUpRescans),
        patches: numberOrNull(stats.patches),
        verifications: numberOrNull(stats.verifications),
        resolutions: numberOrNull(stats.resolutions)
      }
    };
  }

  function normalizeState(raw) {
    const source = isRecord(raw) ? raw : {};
    const summary = isRecord(source.summary) ? source.summary : {};
    const severity = isRecord(summary.severity) ? summary.severity : {};
    const demoNotice =
      typeof source.demoNotice === 'string' && source.demoNotice.length > 0
        ? source.demoNotice
        : '';

    return {
      schemaVersion: numberOrNull(source.schemaVersion),
      dataMode:
        source.dataMode === 'demo' || source.dataMode === 'live' ? source.dataMode : 'empty',
      generatedAt: stringOrNull(source.generatedAt),
      demoNotice,
      sections: arrayOfRecords(source.sections),
      actions: arrayOfRecords(source.actions),
      engine: isRecord(source.engine) ? source.engine : {},
      summary: {
        totalFindings: numberOrNull(summary.totalFindings),
        severity: {
          critical: numberOrNull(severity.critical),
          high: numberOrNull(severity.high),
          medium: numberOrNull(severity.medium),
          low: numberOrNull(severity.low)
        },
        lastScanAt: stringOrNull(summary.lastScanAt),
        workspaceName: stringOrNull(summary.workspaceName)
      },
      vulnerabilityDistribution: arrayOfRecords(source.vulnerabilityDistribution),
      cweDistribution: arrayOfRecords(source.cweDistribution),
      scanHistory: arrayOfRecords(source.scanHistory),
      vulnerabilities: arrayOfRecords(source.vulnerabilities),
      sae: isRecord(source.sae) ? source.sae : {},
      featureInteractions: isRecord(source.featureInteractions) ? source.featureInteractions : {},
      steering: isRecord(source.steering) ? source.steering : {},
      explanations: arrayOfRecords(source.explanations),
      repairs: arrayOfRecords(source.repairs),
      repairHistory: arrayOfRecords(source.repairHistory),
      recommendations: arrayOfRecords(source.recommendations),
      recommendationHistory: arrayOfRecords(source.recommendationHistory),
      feedback: normalizeFeedback(source.feedback),
      verification: isRecord(source.verification) ? source.verification : {},
      reports: arrayOfRecords(source.reports),
      settings: isRecord(source.settings) ? source.settings : {}
    };
  }

  // ---------------------------------------------------------------------
  // Main rendering
  // ---------------------------------------------------------------------

  function render() {
    if (!state) {
      renderBootError();
      return;
    }

    updateChrome();
    updateNavigation();
    renderBanners();
    renderActiveSection();
  }

  function renderBootError() {
    if (dataModeBadge) {
      dataModeBadge.textContent = 'State unavailable';
      dataModeBadge.className = 'badge badge--warning';
    }
    if (demoButton) {
      demoButton.disabled = true;
    }
    if (!content) {
      return;
    }
    clearNode(content);
    content.appendChild(
      emptyState(
        '!',
        'Dashboard state unavailable',
        'The webview could not read the initial dashboard state. Refresh the dashboard. If the ' +
          'problem persists, open the Bug Dhor output channel.'
      )
    );
  }

  function updateChrome() {
    if (!state) {
      return;
    }

    if (dataModeBadge) {
      if (state.dataMode === 'demo') {
        dataModeBadge.textContent = 'Demo data';
        dataModeBadge.className = 'badge badge--warning';
      } else if (state.dataMode === 'live') {
        dataModeBadge.textContent = 'Live data';
        dataModeBadge.className = 'badge badge--info';
      } else {
        dataModeBadge.textContent = 'No scan data';
        dataModeBadge.className = 'badge badge--neutral';
      }
    }

    if (lastUpdated) {
      const generatedAt = state.generatedAt;
      if (generatedAt) {
        lastUpdated.dateTime = generatedAt;
        lastUpdated.textContent = formatDateTime(generatedAt);
      } else {
        lastUpdated.removeAttribute('datetime');
        lastUpdated.textContent = '—';
      }
    }

    if (demoButton) {
      const demo = state.dataMode === 'demo';
      demoButton.hidden = state.dataMode === 'live';
      demoButton.disabled = false;
      demoButton.textContent = demo ? 'Clear demo data' : 'Load demo preview';
      demoButton.setAttribute('aria-pressed', demo ? 'true' : 'false');
    }

    const engine = isRecord(state.engine) ? state.engine : {};
    const engineLabel =
      typeof engine.label === 'string' && engine.label.length > 0
        ? engine.label
        : 'Engine status unavailable';

    if (enginePill) {
      enginePill.classList.toggle('is-ready', isEngineReady(engine.status));
      enginePill.classList.toggle('is-error', engine.status === 'unavailable');
      enginePill.title = typeof engine.detail === 'string' ? engine.detail : engineLabel;
    }
    if (enginePillLabel) {
      enginePillLabel.textContent = engineLabel;
    }

    updateNavCounts();
  }

  function updateNavigation() {
    if (navButtons.length === 0) {
      return;
    }

    for (const button of navButtons) {
      const selected = button.dataset.section === activeSection;
      button.classList.toggle('is-active', selected);
      button.setAttribute('aria-selected', selected ? 'true' : 'false');
      button.tabIndex = selected ? 0 : -1;
    }

    if (content) {
      content.setAttribute('aria-labelledby', `tab-${activeSection}`);
    }
  }

  function updateNavCounts() {
    if (!state) {
      return;
    }

    const saeFeatures =
      state.sae && state.sae.available === true && Array.isArray(state.sae.features)
        ? state.sae.features.length
        : null;
    const interactions =
      state.featureInteractions &&
      state.featureInteractions.available === true &&
      Array.isArray(state.featureInteractions.items)
        ? state.featureInteractions.items.length
        : null;
    const counts = {
      vulnerabilities: state.summary.totalFindings,
      saeFeatures,
      featureInteractions: interactions,
      explanations: state.explanations.length > 0 ? state.explanations.length : null,
      automatedRepair: state.repairs.length > 0 ? state.repairs.length : null,
      researchReports: state.reports.length > 0 ? state.reports.length : null
    };

    for (const element of document.querySelectorAll('[data-nav-count]')) {
      const section = element.dataset.navCount;
      const count = counts[section];
      if (typeof count === 'number' && Number.isFinite(count)) {
        element.hidden = false;
        element.textContent = formatNumber(count);
      } else {
        element.hidden = true;
        element.textContent = '';
      }
    }
  }

  function renderBanners() {
    if (!bannerSlot) {
      return;
    }

    clearNode(bannerSlot);

    if (state && state.dataMode === 'demo') {
      bannerSlot.appendChild(
        banner('warning', 'Demo data preview', state.demoNotice || demoFallbackNotice, false)
      );
    }

    if (transientNotice) {
      bannerSlot.appendChild(
        banner(
          transientNotice.level,
          transientNotice.level === 'error'
            ? 'Error'
            : transientNotice.level === 'warning'
              ? 'Warning'
              : 'Notice',
          transientNotice.message,
          true
        )
      );
    }
  }

  function renderActiveSection() {
    if (!content || !state) {
      return;
    }

    clearNode(content);
    content.setAttribute('aria-busy', 'false');

    let section;
    switch (activeSection) {
      case 'scan':
        section = renderScanSection();
        break;
      case 'vulnerabilities':
        section = renderVulnerabilitiesSection();
        break;
      case 'saeFeatures':
        section = renderSaeSection();
        break;
      case 'featureInteractions':
        section = renderInteractionsSection();
        break;
      case 'securitySteering':
        section = renderSteeringSection();
        break;
      case 'explanations':
        section = renderExplanationsSection();
        break;
      case 'automatedRepair':
        section = renderRepairSection();
        break;
      case 'verification':
        section = renderVerificationSection();
        break;
      case 'researchReports':
        section = renderReportsSection();
        break;
      case 'settings':
        section = renderSettingsSection();
        break;
      default:
        section = renderOverviewSection();
    }

    content.appendChild(section);
  }

  // ---------------------------------------------------------------------
  // Sections
  // ---------------------------------------------------------------------

  function renderOverviewSection() {
    const section = sectionContainer('overview', [
      internalButton('View vulnerabilities', 'vulnerabilities'),
      internalButton('Start a scan', 'scan')
    ]);

    const engineMessage = engineUnavailableCallout();
    if (engineMessage) {
      section.appendChild(engineMessage);
    }

    const summary = state.summary;
    const total = summary.totalFindings;
    const hasData = typeof total === 'number' && Number.isFinite(total);
    const dataNote =
      state.dataMode === 'demo'
        ? 'Illustrative demo value'
        : hasData
          ? 'Latest completed scan'
          : 'No scan data';

    const kpis = el('div', 'kpi-grid');
    kpis.appendChild(kpi('Total findings', total, dataNote));
    for (const severity of severityOrder) {
      const count = summary.severity[severity];
      const note =
        typeof count === 'number' && hasData && total > 0
          ? `${formatPercent(count, total)} of findings`
          : dataNote;
      kpis.appendChild(kpi(severityLabels[severity], count, note, severityTones[severity]));
    }
    section.appendChild(kpis);

    const distributionGrid = el('div', 'split-grid');
    distributionGrid.appendChild(
      card(
        'Vulnerability distribution',
        'Findings by severity in the current data set.',
        distributionList(state.vulnerabilityDistribution, true)
      )
    );
    distributionGrid.appendChild(
      card(
        'CWE distribution',
        'Findings grouped by Common Weakness Enumeration.',
        distributionList(state.cweDistribution, false)
      )
    );
    section.appendChild(distributionGrid);

    const statusGrid = el('div', 'split-grid');
    statusGrid.appendChild(renderVerificationSummaryCard());
    statusGrid.appendChild(
      card('Recent scan history', 'The most recent recorded scan runs.', scanHistoryContent(5))
    );
    section.appendChild(statusGrid);

    return section;
  }

  function renderScanSection() {
    const section = sectionContainer('scan');
    const engineMessage = engineUnavailableCallout();
    if (engineMessage) {
      section.appendChild(engineMessage);
    }

    const actions = actionGrid('scan');
    if (actions) {
      section.appendChild(
        card(
          'Run a security scan',
          'Commands run through the VS Code command layer and require a saved editor or workspace.',
          actions
        )
      );
    }

    section.appendChild(
      card(
        'Scan history',
        'Recorded scan runs and their outcomes. No scan is started by opening this section.',
        scanHistoryContent()
      )
    );

    return section;
  }

  function renderVulnerabilitiesSection() {
    const section = sectionContainer('vulnerabilities', [
      internalButton('Go to Security Scan', 'scan')
    ]);

    if (state.vulnerabilities.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No findings available',
          'No vulnerability findings have been recorded for this workspace. Run a scan once the ' +
            'security engine is connected. No findings are inferred by the dashboard.'
        )
      );
      return section;
    }

    const findings = [...state.vulnerabilities].sort(compareFindings);
    const cwes = [
      ...new Set(findings.map((finding) => stringOrNull(finding.cwe)).filter(Boolean))
    ].sort();
    if (vulnerabilityFilter.cwe !== 'all' && !cwes.includes(vulnerabilityFilter.cwe)) {
      vulnerabilityFilter.cwe = 'all';
    }

    const toolbar = el('div', 'table-toolbar');
    const filters = el('div', 'filter-row');
    filters.appendChild(
      filterGroup(
        'Severity',
        [
          { value: 'all', label: 'All' },
          ...severityOrder.map((severity) => ({
            value: severity,
            label: severityLabels[severity]
          }))
        ],
        vulnerabilityFilter.severity,
        (value) => {
          vulnerabilityFilter.severity = value;
          applyVulnerabilityFilters();
        }
      )
    );

    if (cwes.length > 0) {
      const cweGroup = el('div', 'filter-group');
      const label = el('label', 'filter-label', 'CWE');
      const select = el('select', 'select-control');
      select.id = 'cwe-filter';
      label.htmlFor = select.id;
      select.appendChild(option('all', 'All CWEs'));
      for (const cwe of cwes) {
        select.appendChild(option(cwe, cwe));
      }
      select.value = vulnerabilityFilter.cwe;
      select.addEventListener('change', () => {
        vulnerabilityFilter.cwe = select.value;
        applyVulnerabilityFilters();
      });
      cweGroup.appendChild(label);
      cweGroup.appendChild(select);
      filters.appendChild(cweGroup);
    }

    toolbar.appendChild(filters);
    const visibleCount = el('p', 'toolbar-meta');
    toolbar.appendChild(visibleCount);
    section.appendChild(toolbar);

    const table = createTable({
      caption: 'Vulnerability findings',
      columns: [
        { label: 'ID' },
        { label: 'Finding' },
        { label: 'Severity' },
        { label: 'CWE' },
        { label: 'Location' },
        { label: 'Status' }
      ],
      rows: findings.map((finding) => {
        const row = [
          el('span', 'mono', textOrDash(finding.id)),
          stackedCell(textOrDash(finding.title), stringOrNull(finding.summary)),
          severityBadge(finding.severity),
          el('span', 'mono', textOrDash(finding.cwe)),
          locationCell(finding.file, finding.line),
          statusBadge(finding.status)
        ];
        return row;
      })
    });

    const bodyRows = Array.from(table.tbody.querySelectorAll('tr'));
    bodyRows.forEach((row, index) => {
      const finding = findings[index];
      row.dataset.severity = typeof finding.severity === 'string' ? finding.severity : '';
      row.dataset.cwe = typeof finding.cwe === 'string' ? finding.cwe : '';
    });

    section.appendChild(
      card(
        'Findings',
        'Sorted by severity. Filters apply only to the data already loaded.',
        table.element
      )
    );

    const noMatches = emptyState(
      '—',
      'No findings match these filters',
      'Change the severity or CWE filter to show other findings.'
    );
    noMatches.hidden = true;
    section.appendChild(noMatches);

    function applyVulnerabilityFilters() {
      let shown = 0;
      bodyRows.forEach((row) => {
        const severityMatch =
          vulnerabilityFilter.severity === 'all' ||
          row.dataset.severity === vulnerabilityFilter.severity;
        const cweMatch =
          vulnerabilityFilter.cwe === 'all' || row.dataset.cwe === vulnerabilityFilter.cwe;
        const matches = severityMatch && cweMatch;
        row.hidden = !matches;
        if (matches) {
          shown += 1;
        }
      });

      visibleCount.textContent = `Showing ${formatNumber(shown)} of ${formatNumber(
        findings.length
      )} findings`;
      noMatches.hidden = shown !== 0;

      for (const chip of filters.querySelectorAll('.filter-chip')) {
        const active = chip.dataset.filterValue === vulnerabilityFilter.severity;
        chip.classList.toggle('is-active', active);
        chip.setAttribute('aria-pressed', active ? 'true' : 'false');
      }
      if (cwes.length > 0) {
        const select = filters.querySelector('#cwe-filter');
        if (select) {
          select.value = vulnerabilityFilter.cwe;
        }
      }
    }

    applyVulnerabilityFilters();
    return section;
  }

  function renderSaeSection() {
    const section = sectionContainer('saeFeatures');
    const actions = actionGrid('saeFeatures');
    if (actions) {
      section.appendChild(actions);
    }

    const sae = isRecord(state.sae) ? state.sae : {};
    if (sae.available !== true) {
      section.appendChild(
        callout(
          'SAE features unavailable',
          typeof sae.message === 'string' && sae.message.length > 0
            ? sae.message
            : 'No compatible SAE artifact and model activation source are registered.',
          'warning'
        )
      );
      section.appendChild(
        requirementsCard('Capabilities required for SAE features', [
          'A registered, compatible SAE artifact with a verified checksum.',
          'A white-box model whose internal activations are accessible at the declared hook point.',
          'Token-to-source alignment coverage reported by the backend.',
          'A recorded feature run tied to the model revision, SAE hash, and source snapshot.'
        ])
      );
      return section;
    }

    const features = Array.isArray(sae.features) ? arrayOfRecords(sae.features) : [];
    if (features.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No feature run has been recorded',
          'The SAE capability is available, but no feature extraction run has produced data for ' +
            'this workspace. No activation values are inferred.'
        )
      );
    } else {
      section.appendChild(
        card(
          'Measured features',
          'Activation statistics come from the recorded SAE run. Values are not probabilities.',
          createTable({
            caption: 'Measured SAE features',
            columns: [
              { label: 'Feature' },
              { label: 'Label' },
              { label: 'Max activation', numeric: true },
              { label: 'Mean activation', numeric: true },
              { label: 'Count', numeric: true },
              { label: 'Layer', numeric: true }
            ],
            rows: features.map((feature) => [
              el('span', 'mono', textOrDash(feature.index)),
              stackedCell(
                textOrDash(feature.label),
                stringOrNull(feature.labelSource) ? `Label source: ${feature.labelSource}` : null
              ),
              formatDecimal(feature.maxActivation),
              formatDecimal(feature.meanActivation),
              formatNumber(feature.count),
              textOrDash(feature.layer)
            ])
          }).element
        )
      );
    }

    section.appendChild(renderProvenanceCard(sae.provenance, 'SAE run provenance'));
    return section;
  }

  function renderInteractionsSection() {
    const section = sectionContainer('featureInteractions');
    const actions = actionGrid('featureInteractions');
    if (actions) {
      section.appendChild(actions);
    }

    section.appendChild(
      callout(
        'Model-intervention scope',
        'Counterfactual effects describe model behaviour under the named intervention. They are ' +
          'not real-world causal claims and must not be presented as probabilities.',
        'info'
      )
    );

    const interactions = isRecord(state.featureInteractions) ? state.featureInteractions : {};
    if (interactions.available !== true) {
      section.appendChild(
        callout(
          'Feature interactions unavailable',
          typeof interactions.message === 'string' && interactions.message.length > 0
            ? interactions.message
            : 'No measured activations or counterfactual run are available.',
          'warning'
        )
      );
      return section;
    }

    section.appendChild(renderInteractionEvidence(interactions));

    const items = Array.isArray(interactions.items) ? arrayOfRecords(interactions.items) : [];
    if (items.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No interaction results',
          'No counterfactual comparison has been recorded for this workspace. Effects are not ' +
            'estimated by the dashboard.'
        )
      );
      return section;
    }

    section.appendChild(
      card(
        'Counterfactual comparisons',
        'Effects are reported with their validity and evidence method.',
        createTable({
          caption: 'Feature interaction results',
          columns: [
            { label: 'Features' },
            { label: 'Effect' },
            { label: 'Interval' },
            { label: 'Validity' },
            { label: 'Method' }
          ],
          rows: items.map((item) => [
            describeFeaturePair(item),
            stackedCell(
              formatSignedNumber(item.effect),
              stringOrNull(item.effectKind) ? `Kind: ${item.effectKind}` : null
            ),
            formatInterval(item.interval ?? item.ci),
            validityBadge(item.valid),
            textOrDash(item.method)
          ])
        }).element
      )
    );

    return section;
  }

  function renderInteractionEvidence(interactions) {
    const body = el('div', 'interaction-evidence');
    const baseline = isRecord(interactions.baselineRisk) ? interactions.baselineRisk : null;
    const single = records(interactions.singleFeatureEffects);
    const pairwise = records(interactions.pairwiseEffects);
    const higherOrder = records(interactions.higherOrderEffects);
    const activationChanges = records(interactions.activationChanges);
    const cweResults = records(interactions.cweResults);
    const metadata = isRecord(interactions.metadata) ? interactions.metadata : null;

    const overview = el('div', 'interaction-overview');
    if (baseline) {
      overview.appendChild(
        kpi(
          'Baseline risk',
          baseline.value,
          baseline.scale ? `Scale: ${baseline.scale}` : 'Measured baseline outcome',
          'info',
          true
        )
      );
    } else {
      overview.appendChild(
        kpi('Baseline risk', null, 'Unavailable evidence: no baseline outcome supplied.', 'neutral')
      );
    }
    overview.appendChild(
      kpi(
        'Intervention cells',
        single.length + pairwise.length + higherOrder.length,
        'Measured results supplied by the experiment',
        'neutral'
      )
    );
    overview.appendChild(
      kpi(
        'Activation changes',
        activationChanges.length,
        activationChanges.length > 0
          ? 'Token/layer changes supplied by the experiment'
          : 'Unavailable evidence',
        'neutral'
      )
    );
    body.appendChild(overview);

    const effectItems = [
      ...single.map((item, index) => ({ ...item, kind: 'single', index })),
      ...pairwise.map((item, index) => ({ ...item, kind: 'pairwise', index })),
      ...higherOrder.map((item, index) => ({ ...item, kind: 'higher-order', index }))
    ];
    if (effectItems.length > 0) {
      body.appendChild(
        card(
          'Intervention effects',
          'Bars show only supplied outcome values. The outcome scale and evidence category are experiment-specific.',
          createEffectChart(effectItems)
        )
      );

      const selector = el('select', 'interaction-selector');
      selector.setAttribute('aria-label', 'Select a counterfactual interaction');
      effectItems.forEach((item, index) => {
        const label =
          item.kind === 'single'
            ? `Single feature: ${describeFeatureValue(item)}`
            : `${humanize(item.kind)}: ${describeFeatureList(item)}`;
        selector.appendChild(option(String(index), label));
      });
      const details = el('div', 'interaction-details');
      const detailCard = card(
        'Selected intervention',
        'Inspect the supplied code evidence and measured metadata for this result.',
        [selector, details]
      );
      body.appendChild(detailCard);

      const renderDetails = () => {
        const selected = effectItems[Number(selector.value)];
        details.replaceChildren(selected ? renderInteractionDetails(selected) : unavailableEvidence());
      };
      selector.addEventListener('change', renderDetails);
      renderDetails();
    } else {
      body.appendChild(
        emptyState(
          '—',
          'No intervention effects',
          'The experiment supplied no single-feature, pairwise, or higher-order outcome values. ' +
            'No chart is rendered.'
        )
      );
    }

    if (activationChanges.length > 0) {
      body.appendChild(
        card(
          'Feature activation changes',
          'Before/after values are shown on the activation scale supplied by the experiment.',
          createActivationChart(activationChanges)
        )
      );
    } else {
      body.appendChild(
        callout(
          'Activation changes unavailable',
          'No token-, layer-, or feature-level activation deltas were supplied for visualization.',
          'warning'
        )
      );
    }

    if (cweResults.length > 0) {
      body.appendChild(
        card(
          'CWE-specific outcomes',
          'CWE labels are displayed as supplied; an effect does not establish a change in true vulnerability status.',
          createTable({
            caption: 'CWE-specific counterfactual results',
            columns: [
              { label: 'CWE' },
              { label: 'Outcome' },
              { label: 'Uncertainty' },
              { label: 'Evidence' }
            ],
            rows: cweResults.map((item) => [
              textOrDash(item.cwe),
              formatSignedNumber(item.effect ?? item.outcome),
              formatUncertainty(item.uncertainty),
              evidenceBadge(item.evidenceType)
            ])
          }).element
        )
      );
    } else {
      body.appendChild(
        callout(
          'CWE-specific results unavailable',
          'No CWE-filtered counterfactual outcomes were supplied by the experiment.',
          'warning'
        )
      );
    }

    body.appendChild(
      card(
        'Experiment metadata',
        'Provenance is retained for reproducibility. Missing fields remain unavailable.',
        metadata ? metadataList(metadata) : unavailableEvidence()
      )
    );
    return body;
  }

  function createEffectChart(items) {
    const values = items.map((item) => numericValue(item.effect ?? item.contrast ?? item.outcome));
    const finite = values.filter((value) => value !== null);
    if (finite.length === 0) {
      return unavailableEvidence();
    }
    const max = Math.max(...finite.map((value) => Math.abs(value)), 1);
    const chart = svgElement('svg');
    chart.setAttribute('class', 'interaction-chart');
    chart.setAttribute('viewBox', `0 0 640 ${Math.max(items.length * 38, 90)}`);
    chart.setAttribute('role', 'img');
    chart.setAttribute('aria-label', 'Measured counterfactual intervention effects');
    items.forEach((item, index) => {
      const value = values[index];
      const y = index * 38 + 8;
      const label =
        item.kind === 'single'
          ? `F ${describeFeatureValue(item)}`
          : describeFeatureList(item);
      chart.appendChild(svgText(label.slice(0, 30), 4, y + 16, 'interaction-chart__label'));
      if (value === null) {
        chart.appendChild(svgText('Unavailable evidence', 220, y + 16, 'interaction-chart__muted'));
        return;
      }
      const width = Math.max((Math.abs(value) / max) * 330, 2);
      const x = value < 0 ? 220 - width : 220;
      const bar = svgElement('rect');
      bar.setAttribute('x', String(x));
      bar.setAttribute('y', String(y));
      bar.setAttribute('width', String(width));
      bar.setAttribute('height', '22');
      bar.setAttribute('rx', '3');
      bar.setAttribute('class', value < 0 ? 'interaction-chart__bar interaction-chart__bar--negative' : 'interaction-chart__bar');
      chart.appendChild(bar);
      chart.appendChild(svgText(formatSignedNumber(value), 560, y + 16, 'interaction-chart__value'));
    });
    const axis = svgElement('line');
    axis.setAttribute('x1', '220');
    axis.setAttribute('x2', '220');
    axis.setAttribute('y1', '0');
    axis.setAttribute('y2', String(Math.max(items.length * 38, 90)));
    axis.setAttribute('class', 'interaction-chart__axis');
    chart.appendChild(axis);
    return chart;
  }

  function createActivationChart(items) {
    const chart = svgElement('svg');
    chart.setAttribute('class', 'interaction-chart interaction-chart--activation');
    chart.setAttribute('viewBox', `0 0 640 ${Math.max(items.length * 46, 90)}`);
    chart.setAttribute('role', 'img');
    chart.setAttribute('aria-label', 'Measured activation changes');
    items.forEach((item, index) => {
      const before = numericValue(item.before);
      const after = numericValue(item.after);
      const delta = numericValue(item.delta);
      const y = index * 46 + 8;
      chart.appendChild(svgText(textOrDash(item.label ?? item.feature ?? item.token), 4, y + 16, 'interaction-chart__label'));
      if (before === null || after === null) {
        chart.appendChild(svgText('Unavailable evidence', 220, y + 16, 'interaction-chart__muted'));
        return;
      }
      const max = Math.max(Math.abs(before), Math.abs(after), 1);
      const beforeWidth = (Math.abs(before) / max) * 220;
      const afterWidth = (Math.abs(after) / max) * 220;
      appendActivationBar(chart, 220, y, beforeWidth, 'Before');
      appendActivationBar(chart, 220, y + 12, afterWidth, 'After');
      chart.appendChild(
        svgText(`Δ ${formatSignedNumber(delta ?? after - before)}`, 560, y + 16, 'interaction-chart__value')
      );
    });
    return chart;
  }

  function appendActivationBar(chart, x, y, width, label) {
    const bar = svgElement('rect');
    bar.setAttribute('x', String(x));
    bar.setAttribute('y', String(y));
    bar.setAttribute('width', String(Math.max(width, 2)));
    bar.setAttribute('height', '8');
    bar.setAttribute('rx', '2');
    bar.setAttribute('class', label === 'Before' ? 'interaction-chart__bar interaction-chart__bar--before' : 'interaction-chart__bar');
    chart.appendChild(bar);
    chart.appendChild(svgText(label, 450, y + 8, 'interaction-chart__muted'));
  }

  function renderInteractionDetails(item) {
    const details = el('div', 'interaction-detail-grid');
    details.appendChild(detailRow('Evidence category', evidenceLabel(item.evidenceType)));
    details.appendChild(detailRow('Outcome scale', item.outcomeScale ?? item.scale));
    details.appendChild(detailRow('Effect', formatSignedNumber(item.effect ?? item.contrast ?? item.outcome)));
    details.appendChild(detailRow('Uncertainty', formatUncertainty(item.uncertainty ?? item.interval ?? item.ci)));
    details.appendChild(detailRow('CWE', Array.isArray(item.cwe) ? item.cwe.join(', ') : item.cwe));

    const examples = Array.isArray(item.examples)
      ? item.examples
      : [...(Array.isArray(item.positiveExamples) ? item.positiveExamples : []),
        ...(Array.isArray(item.negativeExamples) ? item.negativeExamples : [])];
    const examplesNode = el('div', 'interaction-examples');
    examplesNode.appendChild(el('h4', 'interaction-examples__title', 'Code examples'));
    if (examples.length === 0) {
      examplesNode.appendChild(el('p', 'text-muted', 'Unavailable evidence: no code examples supplied.'));
    } else {
      for (const example of examples) {
        const pre = el('pre', 'code-example');
        pre.textContent = isRecord(example) ? String(example.code ?? example.text ?? '') : String(example);
        examplesNode.appendChild(pre);
      }
    }
    details.appendChild(examplesNode);
    return details;
  }

  function metadataList(metadata) {
    const list = el('dl', 'metadata-list');
    for (const [key, value] of Object.entries(metadata)) {
      if (value === null || value === undefined || value === '') {
        continue;
      }
      addSettingsRow(list, humanize(key), Array.isArray(value) ? value.join(', ') : String(value));
    }
    return list.childNodes.length > 0 ? list : unavailableEvidence();
  }

  function detailRow(label, value) {
    const row = el('div', 'interaction-detail-row');
    row.appendChild(el('span', 'interaction-detail-row__label', label));
    row.appendChild(el('span', 'interaction-detail-row__value', textOrDash(value)));
    return row;
  }

  function unavailableEvidence() {
    return callout(
      'Unavailable evidence',
      'This result was not supplied by a measured experiment. The dashboard does not infer or fabricate it.',
      'warning'
    );
  }

  function evidenceBadge(value) {
    return badge(evidenceLabel(value), value ? 'info' : 'warning');
  }

  function evidenceLabel(value) {
    const labels = {
      observed_association: 'Observed association',
      controlled_intervention: 'Controlled intervention',
      estimated_interaction: 'Estimated interaction',
      unavailable: 'Unavailable evidence'
    };
    return labels[value] ?? 'Unavailable evidence';
  }

  function formatUncertainty(value) {
    if (isRecord(value)) {
      if (Array.isArray(value.confidenceInterval)) {
        return `CI [${formatDecimal(value.confidenceInterval[0])}, ${formatDecimal(value.confidenceInterval[1])}]`;
      }
      if (Array.isArray(value.interval)) {
        return `[${formatDecimal(value.interval[0])}, ${formatDecimal(value.interval[1])}]`;
      }
      if (numericValue(value.standardError) !== null) {
        return `SE ${formatDecimal(value.standardError)}`;
      }
    }
    return textOrDash(value, 'Unavailable evidence');
  }

  function records(value) {
    return Array.isArray(value) ? arrayOfRecords(value) : [];
  }

  function numericValue(value) {
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
  }

  function describeFeatureValue(item) {
    return describeFeature(item.feature ?? item.featureId ?? item.featureIndex);
  }

  function describeFeatureList(item) {
    const features = Array.isArray(item.features)
      ? item.features
      : [item.featureA, item.featureB].filter((value) => isDisplayValue(value));
    return features.map(describeFeature).join(' + ') || 'Unavailable evidence';
  }

  function svgElement(tagName) {
    return document.createElementNS(SVG_NAMESPACE, tagName);
  }

  function svgText(value, x, y, className) {
    const text = svgElement('text');
    text.setAttribute('x', String(x));
    text.setAttribute('y', String(y));
    text.setAttribute('class', className);
    text.textContent = value;
    return text;
  }

  function renderSteeringSection() {
    const section = sectionContainer('securitySteering');
    const steering = isRecord(state.steering) ? state.steering : {};

    if (steering.available !== true) {
      section.appendChild(
        callout(
          'Activation steering unavailable',
          typeof steering.message === 'string' && steering.message.length > 0
            ? steering.message
            : 'No compatible white-box model, activation access, and steering-capable SAE are ' +
                'available.',
          'warning'
        )
      );
      section.appendChild(
        requirementsCard('Capabilities required for steering', [
          'A white-box model with accessible internal activations.',
          'A compatible SAE with decoder directions at the steering hook point.',
          'Counterfactual interaction results that define the steering plan.',
          'A paired security and functional evaluation harness.',
          'Explicit user opt-in before any steering run begins.'
        ])
      );
      return section;
    }

    const controls = Array.isArray(steering.controls) ? arrayOfRecords(steering.controls) : [];
    if (controls.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No steering controls',
          'The steering capability is available, but no plan or control has been recorded. No ' +
            'activation steering is performed by the dashboard.'
        )
      );
      return section;
    }

    const list = el('ul', 'check-list');
    for (const control of controls) {
      const item = el('li');
      const copy = el('div', 'check-list__copy');
      copy.appendChild(el('span', null, textOrDash(control.label)));
      if (typeof control.detail === 'string' && control.detail.length > 0) {
        copy.appendChild(el('span', 'check-list__detail', control.detail));
      }
      item.appendChild(copy);
      item.appendChild(controlBadge(control));
      list.appendChild(item);
    }

    section.appendChild(
      card(
        'Steering controls',
        'Controls remain capability-gated and require explicit opt-in.',
        list
      )
    );

    return section;
  }

  function renderExplanationsSection() {
    const section = sectionContainer('explanations');
    const actions = actionGrid('explanations');
    if (actions) {
      section.appendChild(actions);
    }

    section.appendChild(
      callout(
        'Evidence-backed explanations only',
        'Every explanation must state its claim kind and evidence. An explanation without a claim ' +
          'kind is shown as unlabelled, not as a probability.',
        'info'
      )
    );

    if (state.explanations.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No explanations available',
          'No explanation graph has been recorded. Explanations cannot precede the evidence they ' +
            'explain.'
        )
      );
      return section;
    }

    for (const explanation of state.explanations) {
      section.appendChild(renderExplainabilityReport(explanation));
    }

    return section;
  }

  function renderExplainabilityReport(explanation) {
    const report = el('article', 'explanation-report');
    const title = textOrDash(explanation.what ?? explanation.title);
    const cwe = stringOrNull(explanation.cwe);
    const header = el('div', 'card__header');
    const copy = el('div');
    copy.appendChild(el('h3', 'card__title', title));
    if (typeof explanation.findingId === 'string') {
      copy.appendChild(el('p', 'card__description mono', `Finding: ${explanation.findingId}`));
    }
    header.appendChild(copy);
    header.appendChild(cwe ? badge(cwe, 'warning') : badge('CWE unavailable', 'warning'));
    report.appendChild(header);

    const summaryGrid = el('div', 'explanation-grid');
    summaryGrid.appendChild(
      explanationCard(
        'Vulnerability summary',
        'What the backend reports for this finding.',
        definitionList(
          [
            ['What was detected', explanation.what ?? explanation.title],
            ['Potential impact', explanation.potential_security_impact],
            ['Remediation', explanation.recommended_remediation]
          ],
          'Unavailable information: the explanation did not provide a summary.'
        )
      )
    );
    summaryGrid.appendChild(
      explanationCard(
        'CWE classification',
        'Classification is displayed exactly as supplied by the backend.',
        definitionList(
          [
            ['CWE', explanation.cwe],
            ['Finding ID', explanation.findingId],
            ['Provenance', provenanceLabel(explanation.provenance)]
          ],
          'Unavailable information: no CWE classification was supplied.'
        )
      )
    );
    summaryGrid.appendChild(
      explanationCard(
        'Vulnerable code location',
        'Open the affected source line when the backend provides a workspace-contained path.',
        renderExplanationLocation(explanation.where ?? explanation.location)
      )
    );
    report.appendChild(summaryGrid);

    const evidenceGrid = el('div', 'explanation-grid');
    evidenceGrid.appendChild(
      explanationCard(
        'Evidence sources',
        'Observed evidence and its provenance.',
        renderEvidenceRecords(
          explanation.directlyObservedEvidence ?? explanation.why_detected,
          'No directly observed evidence was supplied.'
        )
      )
    );
    evidenceGrid.appendChild(
      explanationCard(
        'AST / CFG / DFG visualization',
        'Graph nodes and edges are rendered only when supplied by the backend.',
        renderGraphEvidence(explanation.astCfgDfg ?? explanation.graph)
      )
    );
    evidenceGrid.appendChild(
      explanationCard(
        'Taint propagation path',
        'Potential source-to-sink paths retain their confidence and limitations.',
        renderTaintPaths(explanation.source_to_sink_paths ?? explanation.sourceToSinkPaths)
      )
    );
    report.appendChild(evidenceGrid);

    const researchGrid = el('div', 'explanation-grid');
    researchGrid.appendChild(
      explanationCard(
        'SAE feature activation',
        'SAE values are measurements or associations, not feature meanings.',
        renderResearchRecords(
          explanation.sae_features ?? explanation.saeFeatures,
          'No SAE feature activation evidence was supplied.'
        )
      )
    );
    researchGrid.appendChild(
      explanationCard(
        'Counterfactual feature effects',
        'Controlled intervention results do not prove a change in true vulnerability status.',
        renderResearchRecords(
          explanation.counterfactual_interventions ?? explanation.counterfactuals,
          'No counterfactual intervention evidence was supplied.'
        )
      )
    );
    researchGrid.appendChild(
      explanationCard(
        'Feature interaction analysis',
        'Only experimentally validated interactions should appear here.',
        renderValidatedInteractions(
          explanation.feature_interactions ?? explanation.featureInteractions
        )
      )
    );
    report.appendChild(researchGrid);

    const technical = el('details', 'technical-details');
    const summary = el('summary', null, 'Technical explanation and model-generated claims');
    technical.appendChild(summary);
    const technicalBody = el('div', 'technical-details__body');
    technicalBody.appendChild(
      explanationCard(
        'Model-generated explanations',
        'These claims are hypotheses, not directly observed evidence or causal explanations.',
        renderResearchRecords(
          explanation.model_generated_explanations ?? explanation.modelGeneratedExplanations,
          'No model-generated explanation was supplied.'
        )
      )
    );
    technicalBody.appendChild(
      explanationCard(
        'Uncertainty and unavailable information',
        'Missing evidence is shown explicitly rather than inferred.',
        renderStringList(
          Array.isArray(explanation.limitations) ? explanation.limitations : [],
          'policy-list',
          'No additional limitations were supplied.'
        )
      )
    );
    technicalBody.appendChild(
      explanationCard(
        'Recommended security fixes',
        'Remediation text is supplied by the backend and is not generated by the dashboard.',
        textOrDash(explanation.recommended_remediation, 'Unavailable information.')
      )
    );
    technical.appendChild(technicalBody);
    report.appendChild(technical);
    return report;
  }

  function explanationCard(title, description, body) {
    return card(title, description, body);
  }

  function renderExplanationLocation(location) {
    if (!isRecord(location) || typeof location.path !== 'string') {
      return unavailableEvidence('No source location was supplied.');
    }
    const body = el('div', 'source-location');
    body.appendChild(
      el(
        'p',
        'mono',
        `${location.path}:${numberOrNull(location.startLine) ?? '—'}:${numberOrNull(
          location.startColumn
        ) ?? '—'}`
      )
    );
    const button = el('button', 'button button--secondary source-location__button', 'Open source line');
    button.type = 'button';
    button.addEventListener('click', () => {
      sendMessage({
        type: 'openLocation',
        path: location.path,
        line: location.startLine,
        column: location.startColumn
      });
    });
    body.appendChild(button);
    return body;
  }

  function renderEvidenceRecords(items, emptyMessage) {
    const recordsList = records(items);
    if (recordsList.length === 0) {
      return unavailableEvidence(emptyMessage);
    }
    const list = el('ul', 'evidence-records');
    for (const item of recordsList) {
      const entry = el('li', 'evidence-record');
      const title = item.title ?? item.source ?? item.type ?? item.kind;
      entry.appendChild(el('strong', null, textOrDash(title)));
      const detail = item.detail ?? item.message ?? item.claim ?? item.status;
      if (isDisplayValue(detail)) {
        entry.appendChild(el('span', 'evidence-record__detail', textOrDash(detail)));
      }
      const meta = [
        item.status ?? item.claimKind ?? item.claim_kind,
        item.source,
        item.provenance?.producer
      ]
        .filter(isDisplayValue)
        .map(textOrDash)
        .join(' · ');
      if (meta) {
        entry.appendChild(el('span', 'evidence-record__meta', meta));
      }
      list.appendChild(entry);
    }
    return list;
  }

  function renderGraphEvidence(graph) {
    if (!isRecord(graph)) {
      return unavailableEvidence('Unavailable information: no AST, CFG, or DFG graph was supplied.');
    }
    const nodes = records(graph.nodes);
    const edges = records(graph.edges);
    if (nodes.length === 0 && edges.length === 0) {
      return unavailableEvidence('Unavailable information: the graph contains no nodes or edges.');
    }
    const body = el('div', 'graph-evidence');
    body.appendChild(
      definitionList(
        [
          ['Graph type', graph.type ?? graph.kind],
          ['Nodes', nodes.length],
          ['Edges', edges.length]
        ],
        'Graph metadata unavailable.'
      )
    );
    if (nodes.length > 0) {
      body.appendChild(el('h4', 'subheading', 'Nodes'));
      body.appendChild(renderEvidenceRecords(nodes, 'No graph nodes supplied.'));
    }
    if (edges.length > 0) {
      body.appendChild(el('h4', 'subheading', 'Edges'));
      body.appendChild(renderEvidenceRecords(edges, 'No graph edges supplied.'));
    }
    return body;
  }

  function renderTaintPaths(paths) {
    const pathRecords = records(paths);
    if (pathRecords.length === 0) {
      return unavailableEvidence('Unavailable information: no taint path was supplied.');
    }
    const body = el('div', 'taint-paths');
    for (const path of pathRecords) {
      const details = el('details', 'taint-path');
      details.appendChild(
        el(
          'summary',
          null,
          `${textOrDash(path.sourceRule ?? path.source)} → ${textOrDash(
            path.sinkRule ?? path.sink
          )} · ${textOrDash(path.confidence, 'confidence unavailable')}`
        )
      );
      details.appendChild(
        renderEvidenceRecords(
          [...records(path.steps), path],
          'Unavailable information: no taint steps were supplied.'
        )
      );
      body.appendChild(details);
    }
    return body;
  }

  function renderResearchRecords(items, emptyMessage) {
    return renderEvidenceRecords(items, emptyMessage);
  }

  function renderValidatedInteractions(items) {
    const interactions = records(items).filter(
      (item) => item.validated === true || item.valid === true
    );
    if (interactions.length === 0) {
      return unavailableEvidence(
        'Unavailable information: no validated feature interaction was supplied.'
      );
    }
    return renderEvidenceRecords(interactions, 'No validated interaction evidence supplied.');
  }

  function renderRepairSection() {
    const section = sectionContainer('automatedRepair');
    const actions = actionGrid('automatedRepair');
    if (actions) {
      section.appendChild(actions);
    }

    section.appendChild(
      callout(
        'Source files are never modified silently',
        'Repair proposals are reviewable artifacts. Applying a patch requires an explicit diff ' +
          'review, base-hash revalidation, and user approval in VS Code. This dashboard does not ' +
          'apply patches.',
        'info'
      )
    );

    if (state.repairs.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No repair proposals',
          'No patch proposal has been generated for this workspace. Repairs are not synthesized ' +
            'by the dashboard.'
        )
      );
    }

    for (const repair of state.repairs) {
      const header = el('div', 'card__header');
      const copy = el('div');
      copy.appendChild(el('h3', 'card__title', textOrDash(repair.title ?? repair.id)));
      if (typeof repair.summary === 'string' && repair.summary.length > 0) {
        copy.appendChild(el('p', 'card__description', repair.summary));
      }
      header.appendChild(copy);
      header.appendChild(statusBadge(repair.status));

      const body = el('div', 'card__body');
      body.appendChild(
        definitionList(
          [
            ['Finding', repair.findingId],
            ['Base snapshot', repair.baseSnapshotId],
            ['Generator', repair.generator],
            ['Status', repair.status]
          ],
          'No repair metadata was provided.'
        )
      );

      const files = Array.isArray(repair.files) ? arrayOfRecords(repair.files) : [];
      if (files.length > 0) {
        body.appendChild(el('h4', 'subheading', 'Files in this proposal'));
        const list = el('ul', 'file-list');
        for (const file of files) {
          const item = el('li');
          item.appendChild(el('span', 'mono', textOrDash(file.path)));
          const delta = formatFileDelta(file.additions, file.deletions);
          if (delta) {
            item.appendChild(el('span', 'file-list__delta', delta));
          }
          list.appendChild(item);
        }
        body.appendChild(list);
      }

      if (typeof repair.rationale === 'string' && repair.rationale.length > 0) {
        body.appendChild(el('h4', 'subheading', 'Rationale'));
        body.appendChild(el('p', 'text-muted', repair.rationale));
      }

      if (Array.isArray(repair.riskNotes) && repair.riskNotes.length > 0) {
        body.appendChild(el('h4', 'subheading', 'Risk notes'));
        body.appendChild(renderStringList(repair.riskNotes, 'policy-list'));
      }

      const candidates = Array.isArray(repair.candidates)
        ? arrayOfRecords(repair.candidates)
        : repair.patch
          ? [{ candidateId: 'selected', patch: repair.patch }]
          : [];
      if (candidates.length > 0) {
        body.appendChild(el('h4', 'subheading', 'Repair candidates'));
        for (const candidate of candidates) {
          const candidateCard = el('div', 'repair-candidate');
          candidateCard.appendChild(
            definitionList(
              [
                ['Candidate', candidate.candidateId],
                ['Verification', candidate.verificationStatus ?? repair.verificationStatus ?? 'Not run'],
                ['Security improvement', candidate.securityImprovement ?? 'Unavailable'],
                ['Functional tests', candidate.functionalTestPassRate ?? 'Unavailable'],
                ['Regression tests', candidate.regressionTestsPassed ?? 'Unavailable']
              ],
              'No candidate metadata was supplied.'
            )
          );
          if (typeof candidate.patch === 'string') {
            const diff = el('pre', 'repair-diff', candidate.patch);
            candidateCard.appendChild(diff);
          }
          const controls = el('div', 'button-row');
          const preview = el('button', 'button button--ghost', 'View inline diff');
          preview.type = 'button';
          preview.addEventListener('click', () =>
            sendMessage({
              type: 'viewRepairDiff',
              repairId: repair.id,
              candidateId: candidate.candidateId
            })
          );
          controls.appendChild(preview);
          if (repair.status === 'proposed') {
            const accept = el('button', 'button button--primary', 'Accept patch');
            accept.type = 'button';
            accept.addEventListener('click', () =>
              sendMessage({
                type: 'acceptRepair',
                repairId: repair.id,
                candidateId: candidate.candidateId
              })
            );
            controls.appendChild(accept);
            const reject = el('button', 'button button--ghost', 'Reject patch');
            reject.type = 'button';
            reject.addEventListener('click', () =>
              sendMessage({ type: 'rejectRepair', repairId: repair.id })
            );
            controls.appendChild(reject);
          }
          if (repair.status === 'accepted') {
            const restore = el('button', 'button button--ghost', 'Restore original code');
            restore.type = 'button';
            restore.addEventListener('click', () =>
              sendMessage({ type: 'restoreRepair', repairId: repair.id })
            );
            controls.appendChild(restore);
          }
          candidateCard.appendChild(controls);
          body.appendChild(candidateCard);
        }
      }

      body.appendChild(
        el(
          'p',
          'setting-note',
          'No patch has been applied. Patch review and approval are handled outside this dashboard.'
        )
      );

      const article = el('article', 'card');
      article.appendChild(header);
      article.appendChild(body);
      section.appendChild(article);
    }

    if (state.repairHistory.length > 0) {
      const history = el('details', 'technical-details');
      history.appendChild(el('summary', 'technical-details__summary', 'Repair history'));
      history.appendChild(renderEvidenceRecords(state.repairHistory, 'No repair history recorded.'));
      section.appendChild(history);
    }

    renderRecommendationCards(section);
    renderFeedbackLifecycle(section);
    return section;
  }

  function renderRecommendationCards(section) {
    section.appendChild(
      callout(
        'Secure recommendations are proposals only',
        'Each recommendation shows the exact original source, the verified candidate source, ' +
          'what changed, why it changed, and remaining risks. A recommendation never guarantees ' +
          'perfect security and is never applied without explicit approval.',
        'info'
      )
    );

    if (state.recommendations.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No secure recommendations',
          'Generate Secure Code produces a recommendation only after mandatory syntax, static, ' +
            'security, and functional verification. No candidate is invented by the dashboard.'
        )
      );
      return;
    }

    for (const recommendation of state.recommendations) {
      const header = el('div', 'card__header');
      const copy = el('div');
      copy.appendChild(
        el('h3', 'card__title', textOrDash(recommendation.title ?? recommendation.id))
      );
      if (
        typeof recommendation.explanation?.summary === 'string' &&
        recommendation.explanation.summary.length > 0
      ) {
        copy.appendChild(el('p', 'card__description', recommendation.explanation.summary));
      }
      header.appendChild(copy);
      header.appendChild(statusBadge(recommendation.status ?? recommendation.state));

      const body = el('div', 'card__body');
      body.appendChild(
        definitionList(
          [
            ['Finding', recommendation.findingId],
            ['CWE', recommendation.cwe],
            ['Workflow state', recommendation.state],
            ['Verification', recommendation.verificationStatus],
            ['Requires approval', recommendation.requiresApproval === true ? 'Yes' : 'No'],
            ['Base snapshot', recommendation.baseSnapshotId],
            ['Generator', recommendation.generator]
          ],
          'No recommendation metadata was provided.'
        )
      );

      const explanation = isRecord(recommendation.explanation) ? recommendation.explanation : {};
      for (const [title, key] of [
        ['What changed', 'changes'],
        ['Why it changed', 'why'],
        ['Remaining risks', 'remainingRisks']
      ]) {
        const values = Array.isArray(explanation[key]) ? explanation[key] : [];
        if (values.length === 0) {
          continue;
        }
        body.appendChild(el('h4', 'subheading', title));
        body.appendChild(renderStringList(values, 'policy-list'));
      }
      if (
        typeof explanation.functionalAssurance === 'string' &&
        explanation.functionalAssurance.length > 0
      ) {
        body.appendChild(el('h4', 'subheading', 'Functional assurance'));
        body.appendChild(el('p', 'text-muted', explanation.functionalAssurance));
      }

      if (typeof recommendation.originalCode === 'string') {
        body.appendChild(el('h4', 'subheading', 'Original code'));
        body.appendChild(el('pre', 'repair-diff', recommendation.originalCode));
      }
      if (typeof recommendation.repairedCode === 'string') {
        body.appendChild(el('h4', 'subheading', 'Recommended code'));
        body.appendChild(el('pre', 'repair-diff', recommendation.repairedCode));
      } else {
        body.appendChild(
          callout(
            'No recommended code',
            'No candidate passed every mandatory gate. The explanation above is the only ' +
              'available result; there is no patch to review or apply.',
            'warning'
          )
        );
      }

      const controls = el('div', 'button-row');
      if (recommendation.repairedCode) {
        const preview = el('button', 'button button--ghost', 'View inline diff');
        preview.type = 'button';
        preview.addEventListener('click', () =>
          sendMessage({
            type: 'viewRepairDiff',
            repairId: recommendation.id,
            candidateId: recommendation.candidates?.[0]?.candidateId
          })
        );
        controls.appendChild(preview);
        if (recommendation.status === 'proposed' && recommendation.requiresApproval === true) {
          const accept = el('button', 'button button--primary', 'Accept patch');
          accept.type = 'button';
          accept.addEventListener('click', () =>
            sendMessage({
              type: 'acceptRepair',
              repairId: recommendation.id,
              candidateId: recommendation.candidates?.[0]?.candidateId
            })
          );
          controls.appendChild(accept);
          const reject = el('button', 'button button--ghost', 'Reject patch');
          reject.type = 'button';
          reject.addEventListener('click', () =>
            sendMessage({ type: 'rejectRepair', repairId: recommendation.id })
          );
          controls.appendChild(reject);
        }
        if (recommendation.status === 'accepted') {
          const restore = el('button', 'button button--ghost', 'Restore original code');
          restore.type = 'button';
          restore.addEventListener('click', () =>
            sendMessage({ type: 'restoreRepair', repairId: recommendation.id })
          );
          controls.appendChild(restore);
        }
      }
      if (controls.childElementCount > 0) {
        body.appendChild(controls);
      }

      const article = el('article', 'card');
      article.appendChild(header);
      article.appendChild(body);
      section.appendChild(article);
    }

    if (state.recommendationHistory.length > 0) {
      const history = el('details', 'technical-details');
      history.appendChild(el('summary', 'technical-details__summary', 'Recommendation history'));
      history.appendChild(
        renderEvidenceRecords(state.recommendationHistory, 'No recommendation history recorded.')
      );
      section.appendChild(history);
    }
  }

  function renderFeedbackLifecycle(section) {
    const feedback = isRecord(state.feedback) ? state.feedback : {};
    const findings = arrayOfRecords(feedback.findings);
    const stats = isRecord(feedback.stats) ? feedback.stats : {};
    const statsCard = el('details', 'technical-details');
    statsCard.appendChild(el('summary', 'technical-details__summary', 'Feedback loop activity'));
    statsCard.appendChild(
      definitionList(
        [
          ['Validated scans recorded', stats.scans],
          ['Self-induced scans suppressed', stats.suppressed],
          ['Bounded follow-up rescans', stats.followUpRescans],
          ['Approved patches recorded', stats.patches],
          ['Verifications recorded', stats.verifications],
          ['Findings resolved', stats.resolutions]
        ],
        'No feedback activity has been recorded.'
      )
    );
    section.appendChild(statsCard);

    section.appendChild(
      callout(
        'Resolution requires three independent signals',
        'A finding is resolved only after an explicitly applied Bug Dhor patch, a clean rescan, ' +
          'and passing verification. Hook events, editor changes, or a passing verification alone ' +
          'never resolve a finding.',
        'info'
      )
    );

    if (findings.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No tracked finding lifecycle',
          'The feedback controller records only findings accepted from validated backend scans.'
        )
      );
      return;
    }

    for (const finding of findings) {
      const lifecycle = el('article', 'card');
      const header = el('div', 'card__header');
      header.appendChild(
        el('h3', 'card__title', textOrDash(finding.findingId ?? finding.id, 'Unidentified finding'))
      );
      header.appendChild(statusBadge(finding.state));
      lifecycle.appendChild(header);
      lifecycle.appendChild(
        el(
          'div',
          'card__body',
          definitionList(
            [
              ['State', finding.state],
              ['Document', finding.documentUri],
              ['CWE', finding.cwe],
              ['Patched', finding.patchedAt ? 'Yes' : 'No'],
              ['Clean rescan', finding.rescanCleanAt ? 'Yes' : 'No'],
              ['Verification', finding.lastVerification?.verdict],
              ['Resolved', finding.resolvedAt ?? 'No']
            ],
            'No lifecycle metadata was provided.'
          )
        )
      );
      section.appendChild(lifecycle);
    }
  }

  function renderVerificationSection() {
    const section = sectionContainer('verification');
    const actions = actionGrid('verification');
    if (actions) {
      section.appendChild(actions);
    }

    const verification = isRecord(state.verification) ? state.verification : {};
    const checks = Array.isArray(verification.checks) ? arrayOfRecords(verification.checks) : [];
    const status = stringOrNull(verification.status) || 'not-run';
    const statusLabel = stringOrNull(verification.label) || humanize(status);

    const kpis = el('div', 'kpi-grid');
    kpis.appendChild(
      kpi(
        'Verification status',
        statusLabel,
        'Never treated as a pass by default',
        verificationTone(status),
        true
      )
    );
    kpis.appendChild(
      kpi(
        'Checks recorded',
        checks.length,
        checks.length === 0 ? 'No checks' : 'From the latest run',
        'neutral'
      )
    );
    kpis.appendChild(
      kpi(
        'Last verification',
        verification.lastRunAt ? formatDateTime(verification.lastRunAt) : null,
        verification.lastRunAt ? 'Recorded timestamp' : 'Not run',
        'neutral',
        true
      )
    );
    section.appendChild(kpis);

    if (typeof verification.summary === 'string' && verification.summary.length > 0) {
      section.appendChild(callout('Verification summary', verification.summary, 'info'));
    }

    const sandbox = isRecord(verification.executionSandbox) ? verification.executionSandbox : {};
    section.appendChild(
      callout(
        sandbox.available === true
          ? stringOrNull(sandbox.label) || 'Execution sandbox available'
          : stringOrNull(sandbox.label) || 'Execution sandbox unavailable',
        typeof sandbox.detail === 'string' && sandbox.detail.length > 0
          ? sandbox.detail
          : sandbox.available === true
            ? 'Execution-based checks may run only inside the configured sandbox.'
            : 'Execution-based verification is not attempted without an adequate isolated sandbox.',
        sandbox.available === true ? 'success' : 'warning'
      )
    );

    section.appendChild(
      card(
        'Verification checks',
        'Static, functional, and execution checks reported by the engine.',
        checks.length === 0
          ? emptyState(
              '—',
              'No verification checks recorded',
              'Not run is not a pass. Verification requires an approved repair and an available ' +
                'verification profile.'
            )
          : renderCheckList(checks)
      )
    );

    return section;
  }

  function renderReportsSection() {
    const section = sectionContainer('researchReports');

    if (state.reports.length === 0) {
      section.appendChild(
        emptyState(
          '—',
          'No research reports',
          'No report has been generated for this workspace. Reports must come from recorded runs ' +
            'with model, SAE, analyzer, and configuration provenance.'
        )
      );
      return section;
    }

    section.appendChild(
      card(
        'Generated reports',
        'Reports are listed with their provenance references. This dashboard does not export or ' +
          'fabricate report content.',
        createTable({
          caption: 'Research reports',
          columns: [
            { label: 'Report' },
            { label: 'Generated' },
            { label: 'Scope' },
            { label: 'Format' },
            { label: 'Artifact' }
          ],
          rows: state.reports.map((report) => [
            stackedCell(textOrDash(report.title), stringOrNull(report.id)),
            formatDateTime(report.generatedAt),
            textOrDash(report.scope),
            textOrDash(report.format),
            el('span', 'mono', textOrDash(report.artifactId))
          ])
        }).element
      )
    );

    return section;
  }

  function renderSettingsSection() {
    const section = sectionContainer('settings');

    const buttons = el('div', 'inline-actions');
    buttons.appendChild(
      actionButton('Open VS Code Settings', () => {
        sendMessage({ type: 'openSettings' });
      })
    );
    buttons.appendChild(
      actionButton(
        'Show logs',
        () => {
          sendMessage({ type: 'showLogs' });
        },
        'button button--secondary'
      )
    );

    const settingsCard = card(
      'Extension settings',
      'Read-only values reported by the extension. Change settings in VS Code.',
      (() => {
        const list = el('dl', 'settings-list');
        const settings = state.settings;
        addSettingsRow(list, 'Python path', settingText(settings.pythonPath, 'Automatic'));
        addSettingsRow(list, 'Auto-start engine', settings.autoStart ? 'Enabled' : 'Disabled');
        addSettingsRow(list, 'Log level', settingText(settings.logLevel, 'info'));
        addSettingsRow(
          list,
          'Show status bar item',
          settings.showStatusBarItem === false ? 'Hidden' : 'Shown'
        );
        addSettingsRow(list, 'Dashboard data mode', dataModeBadgeText(state.dataMode));
        addSettingsRow(list, 'Workspace', settingText(state.summary.workspaceName, 'No workspace'));
        addSettingsRow(
          list,
          'Dashboard schema',
          state.schemaVersion === null ? 'Not reported' : String(state.schemaVersion)
        );
        return list;
      })()
    );
    settingsCard.body.appendChild(buttons);
    section.appendChild(settingsCard);

    const engine = isRecord(state.engine) ? state.engine : {};
    section.appendChild(
      card(
        'Engine',
        'The dashboard reflects the engine state reported by the extension host.',
        definitionList(
          [
            ['Status', engine.status],
            ['Label', engine.label],
            ['Detail', engine.detail]
          ],
          'No engine metadata was provided.'
        )
      )
    );

    section.appendChild(
      card(
        'Security and privacy',
        'Dashboard constraints enforced by the extension and webview.',
        renderStringList(
          [
            'Content Security Policy denies network, media, frames, workers, and inline executable code.',
            'Scripts are local files authorized by a per-render nonce.',
            'All dynamic text is rendered with DOM text nodes; the client does not use dynamic innerHTML.',
            'The dashboard is local-first and makes no cloud requests.',
            'The dashboard cannot write source files. Repair application is outside this panel.'
          ],
          'policy-list'
        )
      )
    );

    return section;
  }

  // ---------------------------------------------------------------------
  // Overview cards and shared content
  // ---------------------------------------------------------------------

  function renderVerificationSummaryCard() {
    const verification = isRecord(state.verification) ? state.verification : {};
    const status = stringOrNull(verification.status) || 'not-run';
    const body = el('div', 'stack');

    const statusRow = el('div', 'status-row');
    statusRow.appendChild(statusBadge(verification.status));
    statusRow.appendChild(
      el(
        'span',
        'text-muted',
        verification.lastRunAt
          ? `Last run ${formatDateTime(verification.lastRunAt)}`
          : 'No verification run recorded'
      )
    );
    body.appendChild(statusRow);

    if (typeof verification.summary === 'string' && verification.summary.length > 0) {
      body.appendChild(el('p', 'text-muted', verification.summary));
    }

    const checks = Array.isArray(verification.checks) ? arrayOfRecords(verification.checks) : [];
    if (checks.length > 0) {
      const summary = { passed: 0, failed: 0, other: 0 };
      for (const check of checks) {
        const checkStatus = stringOrNull(check.status);
        if (checkStatus === 'passed') {
          summary.passed += 1;
        } else if (checkStatus === 'failed') {
          summary.failed += 1;
        } else {
          summary.other += 1;
        }
      }
      body.appendChild(
        el(
          'p',
          'text-muted',
          `${formatNumber(summary.passed)} passed · ${formatNumber(
            summary.failed
          )} failed · ${formatNumber(summary.other)} other`
        )
      );
    }

    const sandbox = isRecord(verification.executionSandbox) ? verification.executionSandbox : {};
    body.appendChild(
      callout(
        sandbox.available === true
          ? 'Execution sandbox available'
          : 'Execution sandbox unavailable',
        typeof sandbox.detail === 'string' && sandbox.detail.length > 0
          ? sandbox.detail
          : 'Execution checks depend on a configured isolated sandbox.',
        sandbox.available === true ? 'success' : 'warning'
      )
    );

    body.appendChild(internalButton('Open Verification', 'verification', 'button button--ghost'));

    return card('Verification status', `Current verdict: ${humanize(status)}`, body);
  }

  function scanHistoryContent(limit) {
    const history = state.scanHistory.filter((entry) => isRecord(entry));
    const visible = typeof limit === 'number' ? history.slice(0, limit) : history;

    if (visible.length === 0) {
      return emptyState(
        '—',
        'No scan history',
        'No scan run has been recorded. Starting this dashboard does not start a scan.'
      );
    }

    return createTable({
      caption: 'Recent scan history',
      columns: [
        { label: 'Started' },
        { label: 'Scope' },
        { label: 'Status' },
        { label: 'Findings', numeric: true },
        { label: 'Duration', numeric: true }
      ],
      rows: visible.map((entry) => [
        formatDateTime(entry.startedAt),
        stackedCell(textOrDash(entry.scope), stringOrNull(entry.id)),
        statusBadge(entry.status),
        formatNumber(entry.findings),
        formatDuration(entry.durationMs)
      ])
    }).element;
  }

  function distributionList(items, severityColors) {
    const entries = arrayOfRecords(items).filter(
      (item) => typeof item.count === 'number' && Number.isFinite(item.count)
    );
    if (entries.length === 0) {
      return emptyState(
        '—',
        'No distribution data',
        'No scan result supplies this distribution. The dashboard does not estimate or infer values.'
      );
    }

    const maxCount = Math.max(...entries.map((item) => item.count), 1);
    const list = el('div', 'distribution-list');

    for (const item of entries) {
      const row = el('div', 'distribution-row');
      const meta = el('div', 'distribution-row__meta');
      const labelText = [stringOrNull(item.cwe), stringOrNull(item.label)]
        .filter(Boolean)
        .join(' · ');
      meta.appendChild(el('span', 'distribution-row__label', textOrDash(labelText || item.key)));
      meta.appendChild(el('span', 'distribution-row__count', formatNumber(item.count)));
      row.appendChild(meta);

      const progress = el('progress', `bar${severityBarClass(item, severityColors)}`);
      progress.max = maxCount;
      progress.value = item.count;
      progress.setAttribute(
        'aria-label',
        `${labelText || textOrDash(item.key)}: ${formatNumber(item.count)}`
      );
      row.appendChild(progress);
      list.appendChild(row);
    }

    return list;
  }

  function severityBarClass(item, severityColors) {
    if (!severityColors) {
      return ' bar--accent';
    }
    const key = typeof item.key === 'string' ? item.key : '';
    return severityTones[key] ? ` bar--${severityTones[key]}` : ' bar--accent';
  }

  function renderCheckList(checks) {
    const list = el('ul', 'check-list');
    for (const check of checks) {
      const item = el('li');
      const copy = el('div', 'check-list__copy');
      copy.appendChild(el('span', null, textOrDash(check.label ?? check.id)));
      if (typeof check.detail === 'string' && check.detail.length > 0) {
        copy.appendChild(el('span', 'check-list__detail', check.detail));
      }
      item.appendChild(copy);
      item.appendChild(statusBadge(check.status));
      list.appendChild(item);
    }
    return list;
  }

  function renderEvidenceList(evidence) {
    if (!Array.isArray(evidence) || evidence.length === 0) {
      return el('p', 'text-muted', 'No evidence entries were provided with this result.');
    }

    const list = el('ul', 'evidence-list');
    for (const entry of evidence) {
      const item = el('li');
      if (isRecord(entry)) {
        item.appendChild(el('span', 'evidence-list__label', textOrDash(entry.label ?? entry.kind)));
        const detail = stringOrNull(entry.detail ?? entry.summary);
        if (detail) {
          item.appendChild(el('span', 'evidence-list__detail', detail));
        }
      } else if (typeof entry === 'string') {
        item.textContent = entry;
      } else {
        item.textContent = 'Unsupported evidence entry';
      }
      list.appendChild(item);
    }
    return list;
  }

  function renderStringList(values, className) {
    const list = el('ul', className);
    for (const value of values) {
      if (typeof value === 'string' && value.length > 0) {
        list.appendChild(el('li', null, value));
      }
    }
    return list;
  }

  function renderProvenanceCard(provenance, title) {
    return card(
      title,
      'Provenance must identify the producer, input, and artifact for the recorded result.',
      renderProvenance(isRecord(provenance) ? provenance : {})
    );
  }

  function renderProvenance(provenance) {
    return definitionList([
      ['Producer', provenance.producer],
      ['Artifact', provenance.artifactId ?? provenance.artifact],
      ['Model', provenance.modelId ?? provenance.model],
      ['Revision', provenance.modelRevision ?? provenance.revision],
      ['SAE artifact', provenance.saeArtifactId],
      ['Layer', provenance.layer],
      ['Hook point', provenance.hookPoint],
      ['SHA-256', provenance.sha256],
      ['Created', provenance.createdAt ? formatDateTime(provenance.createdAt) : null]
    ]);
  }

  function definitionList(entries, emptyMessage = 'No provenance record was provided.') {
    const pairs = entries.filter((pair) => isDisplayValue(pair[1]));

    if (pairs.length === 0) {
      return el('p', 'text-muted', emptyMessage);
    }

    const list = el('dl', 'provenance');
    for (const [label, value] of pairs) {
      list.appendChild(el('dt', null, label));
      list.appendChild(el('dd', null, String(value)));
    }
    return list;
  }

  function requirementsCard(title, requirements) {
    return card(
      title,
      'These capabilities are required before this section can produce results.',
      renderStringList(requirements, 'requirement-list')
    );
  }

  function engineUnavailableCallout() {
    const engine = isRecord(state.engine) ? state.engine : {};
    if (engine.status === 'ready') {
      return null;
    }
    const detail =
      typeof engine.detail === 'string' && engine.detail.length > 0
        ? engine.detail
        : 'The local security engine is not reachable. No result is produced.';
    const title =
      typeof engine.label === 'string' && engine.label.length > 0
        ? engine.label
        : 'Analysis capabilities unavailable';
    return callout(title, detail, 'warning');
  }

  function actionGrid(sectionId) {
    const actions = state.actions.filter(
      (action) =>
        action.section === sectionId &&
        typeof action.command === 'string' &&
        safeCommandPattern.test(action.command) &&
        typeof action.title === 'string' &&
        action.title.length > 0
    );

    if (actions.length === 0) {
      return null;
    }

    const grid = el('div', 'action-grid');
    for (const action of actions) {
      const button = el('button', 'action-card');
      button.type = 'button';
      button.appendChild(el('span', 'action-card__title', action.title));
      if (typeof action.description === 'string' && action.description.length > 0) {
        button.appendChild(el('span', 'action-card__description', action.description));
      }
      if (typeof action.meta === 'string' && action.meta.length > 0) {
        button.appendChild(el('span', 'action-card__meta', action.meta));
      }
      button.addEventListener('click', () => {
        sendMessage({ type: 'executeCommand', command: action.command });
      });
      grid.appendChild(button);
    }
    return grid;
  }

  // ---------------------------------------------------------------------
  // DOM helpers
  // ---------------------------------------------------------------------

  function sectionContainer(sectionId, actions) {
    const container = el('div', 'stack');
    container.appendChild(sectionHeading(sectionId, actions));
    return container;
  }

  function sectionHeading(sectionId, actions) {
    const meta = sectionMeta(sectionId);
    const heading = el('div', 'section-heading');
    const copy = el('div', 'section-heading__copy');
    copy.appendChild(el('p', 'section-kicker', 'Bug Dhor'));
    copy.appendChild(el('h2', null, meta.label));
    if (meta.description) {
      copy.appendChild(el('p', 'section-description', meta.description));
    }
    heading.appendChild(copy);

    if (Array.isArray(actions) && actions.length > 0) {
      const actionRow = el('div', 'section-actions');
      for (const action of actions) {
        if (action) {
          actionRow.appendChild(action);
        }
      }
      heading.appendChild(actionRow);
    }

    return heading;
  }

  function sectionMeta(sectionId) {
    const nav = navSections.find((section) => section.id === sectionId);
    const fromState = state.sections.find((section) => section.id === sectionId);
    return {
      label: nav ? nav.label : humanize(sectionId),
      description:
        fromState && typeof fromState.description === 'string' ? fromState.description : ''
    };
  }

  function card(title, description, body, options = {}) {
    const container = el('section', 'card');
    if (title) {
      const header = el('div', 'card__header');
      const copy = el('div');
      copy.appendChild(el('h3', 'card__title', title));
      if (description) {
        copy.appendChild(el('p', 'card__description', description));
      }
      header.appendChild(copy);
      container.appendChild(header);
    }

    const bodyNode = el('div', `card__body${options.flush ? ' card__body--flush' : ''}`);
    if (body) {
      if (isNode(body)) {
        bodyNode.appendChild(body);
      } else if (Array.isArray(body)) {
        for (const child of body) {
          if (child) {
            bodyNode.appendChild(child);
          }
        }
      }
    }
    container.appendChild(bodyNode);
    container.body = bodyNode;
    return container;
  }

  function kpi(label, value, note, tone = 'neutral', textValue = false) {
    const container = el('div', `kpi kpi--${badgeTones.has(tone) ? tone : 'neutral'}`);
    container.appendChild(el('span', 'kpi__label', label));
    const display = textValue
      ? textOrDash(value)
      : typeof value === 'number' && Number.isFinite(value)
        ? formatNumber(value)
        : '—';
    container.appendChild(el('span', `kpi__value${textValue ? ' kpi__value--text' : ''}`, display));
    if (note) {
      container.appendChild(el('span', 'kpi__note', note));
    }
    return container;
  }

  function callout(title, body, tone) {
    const className =
      tone === 'warning' || tone === 'danger' || tone === 'success'
        ? `callout callout--${tone}`
        : 'callout';
    const container = el('div', className);
    container.appendChild(el('p', 'callout__title', title));
    container.appendChild(el('p', 'callout__body', body));
    return container;
  }

  function emptyState(mark, title, body) {
    const container = el('div', 'empty-state');
    container.appendChild(el('span', 'empty-state__mark', mark));
    container.appendChild(el('h3', 'empty-state__title', title));
    container.appendChild(el('p', 'empty-state__body', body));
    return container;
  }

  function banner(level, title, message, dismissible) {
    const className =
      level === 'error'
        ? 'banner banner--error'
        : level === 'info'
          ? 'banner banner--info'
          : 'banner';
    const container = el('div', className);
    const copy = el('div', 'banner__copy');
    copy.appendChild(el('span', 'banner__title', title));
    copy.appendChild(el('span', null, message));
    container.appendChild(copy);

    if (dismissible) {
      const dismiss = el('button', 'banner__dismiss', 'Dismiss');
      dismiss.type = 'button';
      dismiss.addEventListener('click', () => {
        transientNotice = null;
        renderBanners();
      });
      container.appendChild(dismiss);
    }

    return container;
  }

  function createTable({ caption, columns, rows }) {
    const wrap = el('div', 'table-wrap');
    const table = el('table', 'data-table');
    table.appendChild(el('caption', null, caption));

    const thead = el('thead');
    const headerRow = el('tr');
    for (const column of columns) {
      const cell = el('th', column.numeric ? 'data-table__numeric' : null, column.label);
      cell.scope = 'col';
      headerRow.appendChild(cell);
    }
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = el('tbody');
    for (const row of rows) {
      const rowNode = el('tr');
      row.forEach((value, index) => {
        const column = columns[index] || {};
        const cell = el('td', column.numeric ? 'data-table__numeric' : null);
        if (isNode(value)) {
          cell.appendChild(value);
        } else {
          cell.textContent = isDisplayValue(value) ? String(value) : '—';
        }
        rowNode.appendChild(cell);
      });
      tbody.appendChild(rowNode);
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
    return { element: wrap, tbody };
  }

  function filterGroup(labelText, options, selected, onChange) {
    const group = el('div', 'filter-group');
    group.setAttribute('role', 'group');
    group.setAttribute('aria-label', `Filter by ${labelText.toLowerCase()}`);
    group.appendChild(el('span', 'filter-label', labelText));

    for (const optionEntry of options) {
      const active = optionEntry.value === selected;
      const chip = el('button', `filter-chip${active ? ' is-active' : ''}`, optionEntry.label);
      chip.type = 'button';
      chip.dataset.filterValue = optionEntry.value;
      chip.setAttribute('aria-pressed', active ? 'true' : 'false');
      chip.addEventListener('click', () => {
        onChange(optionEntry.value);
      });
      group.appendChild(chip);
    }

    return group;
  }

  function option(value, label) {
    const node = el('option', null, label);
    node.value = value;
    return node;
  }

  function addSettingsRow(list, label, value) {
    list.appendChild(el('dt', 'settings-row__label', label));
    list.appendChild(el('dd', 'settings-row__value', value));
  }

  function stackedCell(primary, secondary) {
    const container = el('span', 'stacked-cell');
    container.appendChild(el('span', 'finding-title', textOrDash(primary)));
    if (typeof secondary === 'string' && secondary.length > 0) {
      container.appendChild(el('span', 'finding-summary', secondary));
    }
    return container;
  }

  function locationCell(file, line) {
    if (typeof file !== 'string' || file.length === 0) {
      return el('span', 'location', '—');
    }
    const location = typeof line === 'number' && Number.isFinite(line) ? `${file}:${line}` : file;
    return el('span', 'location', location);
  }

  function describeFeaturePair(item) {
    const features = Array.isArray(item.features)
      ? item.features
      : [item.featureA, item.featureB].filter((value) => isDisplayValue(value));
    if (features.length === 0) {
      return el('span', 'text-muted', '—');
    }
    return el('span', null, features.map(describeFeature).join(' + '));
  }

  function describeFeature(feature) {
    if (isRecord(feature)) {
      return textOrDash(
        feature.label ?? feature.id ?? feature.index ?? feature.featureIndex,
        'Unlabelled feature'
      );
    }
    return textOrDash(feature);
  }

  function severityBadge(severity) {
    const key = typeof severity === 'string' ? severity.toLowerCase() : '';
    if (severityTones[key]) {
      return badge(severityLabels[key], severityTones[key]);
    }
    return badge(textOrDash(severity, 'Unknown'), 'neutral');
  }

  function statusBadge(status) {
    const key = typeof status === 'string' ? status : '';
    return badge(humanize(textOrDash(key, 'Unknown')), statusTone(key));
  }

  function validityBadge(valid) {
    if (valid === true) {
      return badge('Valid', 'success');
    }
    if (valid === false) {
      return badge('Not valid', 'danger');
    }
    if (typeof valid === 'string' && valid.length > 0) {
      return badge(humanize(valid), valid === 'valid' ? 'success' : 'warning');
    }
    return badge('Unverified', 'warning');
  }

  function controlBadge(control) {
    if (control.requiresOptIn === true) {
      return badge('Opt-in required', 'warning');
    }
    if (control.enabled === true || control.available === true) {
      return badge('Available', 'success');
    }
    return badge('Unavailable', 'neutral');
  }

  function badge(text, tone) {
    return el('span', `badge badge--${badgeTones.has(tone) ? tone : 'neutral'}`, text);
  }

  function internalButton(label, sectionId, className = 'button button--secondary') {
    return actionButton(label, () => activateSection(sectionId, false), className);
  }

  function actionButton(label, onClick, className = 'button') {
    const button = el('button', className, label);
    button.type = 'button';
    button.addEventListener('click', onClick);
    return button;
  }

  function statusTone(status) {
    const key = typeof status === 'string' ? status : '';
    if (key === 'completed' || key === 'passed' || key === 'resolved' || key === 'fixed') {
      return 'success';
    }
    if (key === 'failed' || key === 'error') {
      return 'danger';
    }
    if (
      key === 'partial' ||
      key === 'warning' ||
      key === 'open' ||
      key === 'cancelled' ||
      key === 'skipped' ||
      key === 'not-run'
    ) {
      return 'warning';
    }
    if (key === 'running' || key === 'triaged' || key === 'in-review') {
      return 'info';
    }
    return 'neutral';
  }

  function verificationTone(status) {
    if (status === 'passed') {
      return 'success';
    }
    if (status === 'failed') {
      return 'danger';
    }
    if (status === 'not-run' || status === 'skipped') {
      return 'neutral';
    }
    return 'warning';
  }

  function dataModeBadgeText(mode) {
    if (mode === 'demo') {
      return 'Demo data';
    }
    if (mode === 'live') {
      return 'Live data';
    }
    return 'No scan data';
  }

  function el(tagName, className, text) {
    const node = document.createElement(tagName);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function clearNode(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function isNode(value) {
    return Boolean(value) && typeof value === 'object' && typeof value.nodeType === 'number';
  }

  function isRecord(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }

  function arrayOfRecords(value) {
    return Array.isArray(value) ? value.filter((entry) => isRecord(entry)) : [];
  }

  function numberOrNull(value) {
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
  }

  function stringOrNull(value) {
    return typeof value === 'string' && value.length > 0 ? value : null;
  }

  function isDisplayValue(value) {
    return (
      (typeof value === 'string' && value.length > 0) ||
      (typeof value === 'number' && Number.isFinite(value))
    );
  }

  function textOrDash(value, fallback = '—') {
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
      return String(value);
    }
    return fallback;
  }

  function settingText(value, fallback) {
    return typeof value === 'string' && value.length > 0 ? value : fallback;
  }

  function isEngineReady(status) {
    return status === 'ready' || status === 'available' || status === 'connected';
  }

  function formatNumber(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return '—';
    }
    return new Intl.NumberFormat().format(value);
  }

  function formatPercent(value, total) {
    if (
      typeof value !== 'number' ||
      typeof total !== 'number' ||
      !Number.isFinite(value) ||
      !Number.isFinite(total) ||
      total <= 0
    ) {
      return '—';
    }
    return `${Math.round((value / total) * 100)}%`;
  }

  function formatSignedNumber(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return '—';
    }
    if (value === 0) {
      return '0';
    }
    return `${value > 0 ? '+' : ''}${formatDecimal(value)}`;
  }

  function formatDecimal(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return '—';
    }
    if (Number.isInteger(value)) {
      return formatNumber(value);
    }
    return String(Number(value.toPrecision(4)));
  }

  function formatInterval(interval) {
    if (Array.isArray(interval) && interval.length >= 2) {
      return `[${formatDecimal(interval[0])}, ${formatDecimal(interval[1])}]`;
    }
    if (
      isRecord(interval) &&
      typeof interval.low === 'number' &&
      typeof interval.high === 'number'
    ) {
      return `[${formatDecimal(interval.low)}, ${formatDecimal(interval.high)}]`;
    }
    return '—';
  }

  function formatDateTime(value) {
    if (typeof value !== 'string' || value.length === 0) {
      return '—';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return '—';
    }
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(date);
  }

  function formatDuration(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      return '—';
    }
    if (value < 1000) {
      return `${formatNumber(value)} ms`;
    }
    return `${formatDecimal(value / 1000)} s`;
  }

  function formatFileDelta(additions, deletions) {
    const hasAdditions = typeof additions === 'number' && Number.isFinite(additions);
    const hasDeletions = typeof deletions === 'number' && Number.isFinite(deletions);
    if (!hasAdditions && !hasDeletions) {
      return '';
    }
    return `+${hasAdditions ? formatNumber(additions) : '—'} / -${
      hasDeletions ? formatNumber(deletions) : '—'
    }`;
  }

  function humanize(value) {
    if (typeof value !== 'string' || value.length === 0) {
      return 'Unknown';
    }
    const words = value.replaceAll('_', '-').split('-').filter(Boolean);
    if (words.length === 0) {
      return 'Unknown';
    }
    return words
      .map((word) => {
        if (word.toLowerCase() === 'cwe') {
          return 'CWE';
        }
        if (word.toLowerCase() === 'sae') {
          return 'SAE';
        }
        return `${word.charAt(0).toUpperCase()}${word.slice(1)}`;
      })
      .join(' ');
  }

  function compareFindings(left, right) {
    const leftRank = severityOrder.indexOf(typeof left.severity === 'string' ? left.severity : '');
    const rightRank = severityOrder.indexOf(
      typeof right.severity === 'string' ? right.severity : ''
    );
    const leftValue = leftRank === -1 ? severityOrder.length : leftRank;
    const rightValue = rightRank === -1 ? severityOrder.length : rightRank;
    if (leftValue !== rightValue) {
      return leftValue - rightValue;
    }
    return String(left.id ?? '').localeCompare(String(right.id ?? ''));
  }
})();
