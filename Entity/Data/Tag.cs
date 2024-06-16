using Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.Data;
public class Tag : IAuditable
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public ICollection<Post> Posts { get; set; } = new HashSet<Post>();
    public string UpdatedBy { get; set; }
    public DateTime? LastModified { get; set; }
}
