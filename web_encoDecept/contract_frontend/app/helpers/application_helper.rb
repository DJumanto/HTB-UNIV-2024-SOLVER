# app/helpers/application_helper.rb
module ApplicationHelper
  def render_markdown(text)
    return '' if text.nil? # Return an empty string if text is nil

    # Configure Redcarpet to render Markdown with links and images enabled
    renderer = Redcarpet::Render::HTML.new(filter_html: true)
    markdown = Redcarpet::Markdown.new(renderer, {
      no_intra_emphasis: true,
      autolink: true,
      tables: true,
      fenced_code_blocks: true,
      disable_indented_code_blocks: true,
      strikethrough: true,
      superscript: true
    })

    # Render Markdown to HTML
    markdown.render(text).html_safe
  end
end
