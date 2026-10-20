-- Pandoc filter of the PDF manuals (see "make pdf"): the text between the
-- title of a manual (its first heading) and its first section is moved to the
-- cover page, below the title. The filter runs before the headings are
-- shifted, so the title is still the first block.
function Pandoc(doc)
  local first = 1
  if #doc.blocks > 0 and doc.blocks[1].t == 'Header' and doc.blocks[1].level == 1 then
    first = 2
  end
  local pre = pandoc.Blocks({})
  while #doc.blocks >= first and doc.blocks[first].t ~= 'Header' do
    pre:insert(doc.blocks:remove(first))
  end
  if #pre > 0 then
    doc.meta.abstract = pandoc.MetaBlocks(pre)
  end
  return doc
end
