using Core.Data;
using Core.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.Data;
public class Author : ApplicationUser, IAuditable
{
    public ICollection<Post> Posts { get; set; } = new HashSet<Post>();
    public string UpdatedBy { get; set; } = string.Empty;
    public DateTime? LastModified { get; set; }
}
