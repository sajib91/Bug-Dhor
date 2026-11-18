'use strict';

/** Repository discovery and inventory exports. */
module.exports = {
  discoverRepositoryInventory: require('./repositoryInventory').discoverRepositoryInventory,
  buildWorkspaceFolderMetadata: require('./repositoryInventory').buildWorkspaceFolderMetadata,
  RepositoryInventoryError: require('./repositoryInventory').RepositoryInventoryError,
  GitIgnoreRules: require('./gitignore').GitIgnoreRules,
  parseGitIgnore: require('./gitignore').parseGitIgnore
};
