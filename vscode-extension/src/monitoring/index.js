'use strict';

/** Real-time document monitoring feature exports. */
module.exports = {
  RealtimeMonitor: require('./realtimeMonitor').RealtimeMonitor,
  normalizeSettings: require('./realtimeMonitor').normalizeSettings,
  createCancellationTokenSource: require('./realtimeMonitor').createCancellationTokenSource,
  DocumentVersionTracker: require('./documentVersionTracker').DocumentVersionTracker,
  buildAnalysisPlan: require('./changeAnalyzer').buildAnalysisPlan,
  findFunctionRanges: require('./changeAnalyzer').findFunctionRanges,
  isSupportedLanguage: require('./changeAnalyzer').isSupportedLanguage,
  isPathExcluded: require('./changeAnalyzer').isPathExcluded
};
