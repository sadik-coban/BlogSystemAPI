using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.Data;
public class Post
{
    public Guid Id { get; set; }
    public Guid AuthorId { get; set; }
    public Guid CategoryId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public Author Author { get; set; } = null!;
    public Category Category { get; set; } = null!;
    public ICollection<Tag> Tags { get; set; } = new HashSet<Tag>();
}