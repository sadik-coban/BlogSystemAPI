using Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Data;
public class UnitOfWork : IUnitOfWork
{
    private readonly ApplicationDbContext _appDbContext;

    public UnitOfWork(ApplicationDbContext appDbContext)
    {
        _appDbContext = appDbContext;
    }

    public void Commit()
    {
        _appDbContext.SaveChanges();
    }

    public async Task CommitAsync()
    {
        await _appDbContext.SaveChangesAsync();
    }
}