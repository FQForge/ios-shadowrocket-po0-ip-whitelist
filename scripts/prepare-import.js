'use strict';

const { readFile, writeFile } = require('node:fs/promises');
const { join } = require('node:path');

async function main() {
  const [repository, ref = 'main', ...extra] = process.argv.slice(2);
  const repoName = /^[a-z0-9-]+\/[a-z0-9_.-]+$/i;
  const invalidSegment = (piece) => !/^[a-z0-9_.-]+$/i.test(piece) || piece === '.' || piece === '..';
  if (!repository || extra.length || !repoName.test(repository)
      || repository.split('/').some(invalidSegment) || ref.split('/').some(invalidSegment)) {
    throw new Error('用法：npm run prepare:import -- OWNER/REPO [分支、标签或提交 SHA]');
  }

  const root = join(__dirname, '..');
  const modulePath = join(root, 'shadowrocket', 'public-ip-whitelist.srmodule');
  const readmePath = join(root, 'README.md');
  const [module, readme] = await Promise.all([
    readFile(modulePath, 'utf8'),
    readFile(readmePath, 'utf8'),
  ]);
  const raw = `https://raw.githubusercontent.com/${repository}/${ref}/shadowrocket`;
  const moduleUrl = `${raw}/public-ip-whitelist.srmodule`;
  const scriptUrl = `${raw}/public-ip-whitelist.js`;
  const importUrl = `shadowrocket://install?module=${encodeURIComponent(moduleUrl)}`;

  const scriptLinks = /script-path=[^,\r\n]+/g;
  const readmeLinks = /<!-- import:start -->[\s\S]*?<!-- import:end -->/;
  if ((module.match(scriptLinks) || []).length !== 2 || !readmeLinks.test(readme)) {
    throw new Error('找不到两条 script-path 或 README 的导入链接区块');
  }

  await writeFile(modulePath, module.replace(scriptLinks, `script-path=${scriptUrl}`));
  const links = [
    '<!-- import:start -->',
    `Raw 地址可直接复制到小火箭的模块添加页面。[查看模块](${moduleUrl})`,
    '',
    '```text',
    moduleUrl,
    '```',
    '',
    '也可以将下面的地址粘贴到 iPhone 的 Safari 地址栏，确认打开 Shadowrocket。',
    '',
    '```text',
    importUrl,
    '```',
    '<!-- import:end -->',
  ].join('\n');
  await writeFile(readmePath, readme.replace(readmeLinks, links));

  console.log(`Raw 模块地址 ${moduleUrl}`);
  console.log(`小火箭导入地址 ${importUrl}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
